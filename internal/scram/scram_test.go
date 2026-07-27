package scram_test

import (
	"encoding/hex"
	"testing"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
	"github.com/vitikevich-landau/go_fileshare/internal/scram"
)

// testIters держит вывод ключа быстрым; действующее значение приезжает из
// конфига (auth.pbkdf2_iters, §19.3) и в математике роли не играет.
const testIters = 4096

// legacySalt — соль §6.2 п. 2 в том виде, в каком её выводит клиент до раунда
// AUTH_PARAMS. Литерал повторён здесь СОЗНАТЕЛЬНО, а не взят из
// domain.LegacySalt: вектора ниже фиксируют байты, которые уже лежат в
// users.json и в users.stored_key работающих установок, и вычислять ожидаемое
// значение той же функцией, которую проверяем, значило бы не проверять ничего.
func legacySalt(login string) []byte { return []byte("fileshare-v2:" + login) }

// TestGoldenVectors — вектора, снятые с реализации ДО выделения пакета из
// internal/auth.
//
// Тест нужен именно этому пакету и именно сейчас. Переезд математики не имеет
// права изменить ни одного байта: stored_key уже лежит в users.json действующих
// установок и переносится в users.stored_key миграцией §21.4, а ClientProof
// считает выпущенный v2-клиент, который никто не обновит. Круговые тесты
// («сгенерировали proof — проверили proof») эту ошибку не видят: они сойдутся и
// на другой соли, и на другом порядке XOR, и на другой метке HMAC — сойдутся с
// собой, разойдясь со всем, что уже развёрнуто.
func TestGoldenVectors(t *testing.T) {
	const (
		login    = "vit"
		password = "correct horse battery staple"
	)
	challenge := []byte("0123456789abcdef") // 16 байт, как proto.ChallengeLen
	salt := legacySalt(login)

	for _, tc := range []struct {
		name string
		got  [scram.KeyLen]byte
		want string
	}{
		{"ClientKey", scram.ClientKey(password, salt, testIters),
			"0743e329167b023923ff5ff4285ab44380cd4f716ae8d608aef6a759ce588325"},
		{"StoredKey", scram.StoredKey(password, salt, testIters),
			"ad9af181756fa2529c8b68c29905a1f48ccaf3e4bc5f3d588f626bdacfafdbd8"},
		{"ClientProof", scram.Prove(password, salt, testIters, challenge, login),
			"39f3769740ff501c2cbe9b0bd9375fc85c98b88d4a3a9745e8c202e6c3f7b22d"},
	} {
		if got := hex.EncodeToString(tc.got[:]); got != tc.want {
			t.Errorf("%s = %s, want %s: цепочка ключей изменилась, выпущенные клиенты перестанут входить",
				tc.name, got, tc.want)
		}
	}
}

// TestStoredKeyIsHashOfClientKey — §6.2 определяет колонку как SHA256(ClientKey),
// и это определение, а не деталь: на нём держится «кража верификатора не даёт
// войти».
func TestStoredKeyIsHashOfClientKey(t *testing.T) {
	salt := legacySalt("vit")
	ck := scram.ClientKey("pw", salt, testIters)
	if scram.StoredKey("pw", salt, testIters) != scram.StoredKeyOf(ck) {
		t.Fatal("StoredKey != SHA256(ClientKey)")
	}
}

// TestVerify — таблица отказов. Каждая строка меняет РОВНО один вход
// доказательства, поэтому проверяется, что связывает proof именно этот вход.
func TestVerify(t *testing.T) {
	const login, password = "vit", "hunter2"
	salt := legacySalt(login)
	challenge := []byte("aaaaaaaaaaaaaaaa")
	stored := scram.StoredKey(password, salt, testIters)

	tests := []struct {
		name  string
		proof scram.Proof
		// подписи проверки
		storedKey scram.Key
		challenge []byte
		login     string
		want      bool
	}{
		{
			name:  "верное доказательство",
			proof: scram.Prove(password, salt, testIters, challenge, login),
			want:  true,
		},
		{
			name:  "другой пароль",
			proof: scram.Prove("wrong", salt, testIters, challenge, login),
		},
		{
			// Повтор перехваченного доказательства на новом вызове: challenge
			// входит в authMessage, поэтому замок не снимается.
			name:      "повтор на новом challenge",
			proof:     scram.Prove(password, salt, testIters, challenge, login),
			challenge: []byte("bbbbbbbbbbbbbbbb"),
		},
		{
			// Доказательство, выведенное для другого логина: логин входит и в
			// соль (§6.2 п. 2), и в authMessage.
			name:  "доказательство другого логина",
			proof: scram.Prove(password, legacySalt("bob"), testIters, challenge, "bob"),
		},
		{
			name:  "другое число итераций",
			proof: scram.Prove(password, salt, testIters*2, challenge, login),
		},
		{
			name:  "другая соль при том же пароле",
			proof: scram.Prove(password, legacySalt("someone-else"), testIters, challenge, login),
		},
		{
			name:  "нулевое доказательство",
			proof: scram.Proof{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := stored
			if tt.storedKey != (scram.Key{}) {
				key = tt.storedKey
			}
			ch := challenge
			if tt.challenge != nil {
				ch = tt.challenge
			}
			lg := login
			if tt.login != "" {
				lg = tt.login
			}
			if got := scram.Verify(key, ch, lg, tt.proof); got != tt.want {
				t.Fatalf("Verify = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestVerifyRejectsProofForAnotherUsersKey — верификатор одного пользователя не
// принимает доказательство другого даже при одинаковом пароле. Это следствие
// того, что соль привязана к логину (§6.2 п. 2), и ровно та причина, по которой
// смена логина до M14 запрещена: она обесценила бы stored_key.
func TestVerifyRejectsProofForAnotherUsersKey(t *testing.T) {
	const password = "same-password"
	challenge := []byte("cccccccccccccccc")

	alice := scram.StoredKey(password, legacySalt("alice"), testIters)
	bobProof := scram.Prove(password, legacySalt("bob"), testIters, challenge, "bob")

	if scram.Verify(alice, challenge, "alice", bobProof) {
		t.Fatal("доказательство bob принято против верификатора alice")
	}
}

// TestKeyLenMatchesProto — KeyLen обязан совпадать с proto.ProofLen и
// proto.ChecksumLen (§6.2: stored_key — SHA256(ClientKey) при ЛЮБОМ kdf_algo).
//
// Пакет scram импортировать proto не вправе (§4.3), поэтому значение объявлено
// дважды, а сверка вынесена во внешний тестовый пакет — тем же приёмом, что
// TestMaxNameLenMatchesProto (§5.3 п. 6). Расхождение объявлений дало бы
// обрезанный верификатор или обрезанное доказательство: кадр разобрался бы, а
// вход перестал работать.
func TestKeyLenMatchesProto(t *testing.T) {
	if scram.KeyLen != proto.ProofLen {
		t.Errorf("scram.KeyLen = %d, proto.ProofLen = %d: значения разъехались", scram.KeyLen, proto.ProofLen)
	}
	if scram.KeyLen != proto.ChecksumLen {
		t.Errorf("scram.KeyLen = %d, proto.ChecksumLen = %d: значения разъехались", scram.KeyLen, proto.ChecksumLen)
	}
}
