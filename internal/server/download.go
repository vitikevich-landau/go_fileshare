package server

import (
	"context"
	"io"
	"os"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
	"github.com/vitikevich-landau/go_fileshare/internal/vfs"
)

// startDownload проверяет запрос и при успехе отдаёт файл ИЗ ОТДЕЛЬНОЙ горутины,
// чтобы читатель оставался свободен для PING/DOWNLOAD_CANCEL, а события могли
// проталкиваться посреди стрима (docs/tz/09-go-port.md §5.5). На сессию
// разрешена лишь одна активная передача (охраняется CompareAndSwap).
func (s *Server) startDownload(sess *Session, req proto.DownloadRequest) {
	if !sess.downloading.CompareAndSwap(false, true) {
		sess.sendMsg(proto.Error{Code: proto.ErrBadRequest, Message: "a transfer is already in progress"})
		return
	}
	f, info, err := s.vfs.Open(req.Path)
	if err != nil {
		sess.downloading.Store(false)
		s.sendErr(sess, vfs.CodeOf(err))
		return
	}
	total := uint64(info.Size())
	if req.Offset > total {
		f.Close()
		sess.downloading.Store(false)
		s.sendErr(sess, proto.ErrUnsupportedOffset)
		return
	}

	tid := s.nextTransfer.Add(1)
	cancel := make(chan struct{})
	sess.setCancel(tid, cancel)
	s.activeDownloads.Add(1)
	sess.wg.Add(1)
	go func() {
		defer sess.wg.Done()
		defer s.activeDownloads.Add(-1)
		defer f.Close()
		defer sess.touch() // освежаем часы простоя, чтобы «после закачки» не скосили (RR-1)
		defer sess.downloading.Store(false)
		defer sess.clearCancel()  // запоздавшая отмена не должна задеть следующую передачу (R3-2)
		defer sess.clearCurPath() // чистим, даже если ошибка checksum/чтения (bug #2)

		// Контекст, который отменяется при отмене передачи ИЛИ сворачивании сессии,
		// чтобы ожидание rate-limit не могло зависнуть ни на том, ни на другом.
		ctx, ctxCancel := context.WithCancel(context.Background())
		defer ctxCancel()
		go func() {
			// Отменяем ctx лимитера при отмене клиентом ИЛИ teardown, чтобы отмена,
			// пришедшая, пока стрим заблокирован в limiter.Wait, разбудила его сразу,
			// а не ждала минутами на низком bps (R3-1). Цикл стрима различает эти два
			// случая: при отмене клиентом шлёт терминальный CANCELLED, чтобы соединение
			// осталось в согласии (RR-3); при teardown просто останавливается. ctx.Done()
			// также позволяет этому наблюдателю выйти при штатном завершении — горутина
			// не утекает.
			select {
			case <-sess.done:
			case <-cancel:
			case <-ctx.Done():
			}
			ctxCancel()
		}()

		sess.setCurPath(req.Path) // ставим до ACCEPT, чтобы drain видел активную передачу (bug #5)
		s.streamFile(ctx, sess, f, req, tid, total, cancel)
	}()
}

// streamFile отдаёт файл чанками от offset до total, соблюдая лимиты скорости, и
// завершает передачу контрольной суммой. Тонкость: на каждом шаге проверяется
// отмена/teardown, а размер чтения ограничивается объявленным остатком, чтобы
// дозапись в файл посреди передачи не заставила превысить total_size.
func (s *Server) streamFile(ctx context.Context, sess *Session, f *os.File, req proto.DownloadRequest, tid TransferID, total uint64, cancel chan struct{}) {
	if req.Offset > 0 {
		if _, err := f.Seek(int64(req.Offset), io.SeekStart); err != nil {
			s.sendErr(sess, proto.ErrInternal)
			return
		}
	}
	if !sess.sendMsg(proto.DownloadAccept{TransferID: tid, TotalSize: total}) {
		return
	}

	clientKey := sess.Login()
	buf := make([]byte, proto.ChunkSize)
	sent := req.Offset
	for sent < total {
		select {
		case <-cancel:
			// Клиент попросил отмену: шлём определённый терминальный кадр после уже
			// поставленных в очередь чанков, чтобы цикл клиента завершился в согласии (RR-3).
			s.sendErr(sess, proto.ErrCancelled)
			return
		case <-sess.done:
			return
		default:
		}
		// Ограничиваем чтение объявленным остатком, чтобы дозапись в файл посреди
		// передачи не заставила превысить total_size (который клиент отвергнет);
		// отдаём ровно изначально объявленный префикс.
		toRead := buf
		if rem := total - sent; rem < uint64(len(buf)) {
			toRead = buf[:rem]
		}
		n, err := f.Read(toRead)
		if n > 0 {
			// Тормозим по ТЕКУЩИМ лимитам, чтобы живое изменение конфига применилось
			// к этой активной передаче (docs/tz/09-go-port.md §5.6).
			lim := s.hub.Current().Limits
			if werr := s.limiter.Wait(ctx, clientKey, lim.PerClientBps, lim.GlobalBps, n); werr != nil {
				// Ожидание прервано. Если клиент попросил отмену — шлём терминальный
				// CANCELLED, чтобы его цикл завершился в согласии (R3-1); при teardown
				// просто останавливаемся (соединение и так закрывается).
				select {
				case <-cancel:
					s.sendErr(sess, proto.ErrCancelled)
				default:
				}
				return
			}
			// proto.Encode копирует buf в новый кадр, поэтому buf можно переиспользовать.
			if !sess.sendMsg(proto.ChunkData{TransferID: tid, Data: buf[:n]}) {
				return
			}
			sess.bytes.Add(uint64(n))
			s.bytesSent.Add(uint64(n))
			sent += uint64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			// Ошибка чтения посреди передачи: сообщаем клиенту, а не оставляем его
			// ждать, и никогда не публикуем частичный файл (CR-02).
			s.sendErr(sess, proto.ErrInternal)
			return
		}
	}

	// Если файл ужался во время передачи, мы отдали меньше байт, чем объявили;
	// сообщаем об ошибке, а не «успешный» DONE, который клиент (справедливо)
	// отвергнет (CR-02).
	if sent != total {
		s.sendErr(sess, proto.ErrInternal)
		return
	}

	// Сервер всегда шлёт контрольную сумму всего файла; при докачке клиент сверяет
	// с ней пересобранный файл. Если сумму посчитать не удалось, мы НЕ должны
	// заявлять успех — шлём ошибку, чтобы клиент не опубликовал непроверяемый файл.
	// Хеш учитывает ctx, поэтому отмена во время подсчёта суммы большого файла (при
	// промахе кэша) прерывает его сразу, а не блокирует на минуты (R4-3).
	_, algo, sum, cerr := s.vfs.ChecksumCtx(ctx, req.Path)
	if cerr != nil {
		// Отмена/teardown во время подсчёта суммы: при отмене клиентом шлём
		// терминальный CANCELLED (держит соединение в согласии); при teardown просто
		// останавливаемся. Любой другой сбой суммы — внутренняя ошибка.
		if ctx.Err() != nil {
			select {
			case <-cancel:
				s.sendErr(sess, proto.ErrCancelled)
			default:
			}
			return
		}
		s.sendErr(sess, proto.ErrInternal)
		return
	}
	if algo != proto.AlgoSHA256 {
		s.sendErr(sess, proto.ErrInternal)
		return
	}
	// Отмена, пришедшая после подсчёта суммы, но до DONE, всё равно побеждает —
	// отменённая передача никогда не отчитывается успехом (R4-3).
	select {
	case <-cancel:
		s.sendErr(sess, proto.ErrCancelled)
		return
	case <-sess.done:
		return
	default:
	}
	if sess.sendMsg(proto.DownloadDone{TransferID: tid, Algo: algo, Checksum: sum}) {
		s.completed.Add(1)
	}
}
