// profile_test.go — гард пайплайна «подписка → профиль»: скачивание, выбор
// парсера, разбор метаданных из заголовков и запись в БД.
//
// ПОЧЕМУ ЛОКАЛЬНЫЙ СЕРВЕР. До 2026-07-26 тест ходил в сеть за
// raw.githubusercontent.com/twilgate/inhive-core/.../test.configs/warp и падал
// ВСЕГДА: такого файла нет ни в этом репозитории, ни в его истории, ни у
// апстрима hiddify-core — URL достался от hiddify-next (ДРУГОЙ репозиторий) и
// пережил ребрендинг только как строка. raw отдаёт 404 с телом «404: Not
// Found», а downloadProfileContent (profile_repository.go:278) отклоняет лишь
// статус 401 — HTML-страница 404 уезжала в парсер, и тест сообщал
// «[SingboxParser] Incorrect Json Format», то есть врал о причине.
// Подписку отдаёт httptest, фикстура лежит в testdata/.
//
// ⚠️ Первая попытка скачивания идёт через SOCKS 127.0.0.1:12334
// (profile_repository.go:249) — если на машине поднят InHive, запрос к
// httptest уйдёт через прокси на тот же loopback и всё равно дойдёт; если нет
// — мгновенный ECONNREFUSED и фолбэк на прямой запрос. Сети в обоих случаях
// не требуется.
//
// Запуск (теги обязательны, без них registry sing-box неполон):
//
//	cd core && TAGS=$(sed -n 's/^BASE_TAGS=//p' Makefile|head -1) \
//	  go test -tags "$TAGS" ./v2/profile/...
package test

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/twilgate/inhive-core/v2/profile"
)

// Метаданные подписки — ровно те, что отдаёт боевой эндпоинт. Один набор
// констант питает ОБА пути их доставки (HTTP-заголовки и комментарии в теле),
// поэтому кейсы не могут разъехаться между собой.
const (
	subTitle       = "🔥 WARP 🔥"
	subTitleHeader = "base64:8J+UpSBXQVJQIPCflKU=" // base64(subTitle)
	subUserInfo    = "upload=0; download=0; total=10737418240000000; expire=2546249531"
	subSupportURL  = "https://t.me/inhive_bot"
	subWebPageURL  = "https://inhive.ru"
	subInterval    = "24" // часы; в ProfileOptions уезжает в миллисекундах

	subTotal  = int64(10737418240000000)
	subExpire = int64(2546249531)
)

// subHeaders — метаданные в виде HTTP-заголовков (как их шлёт сервер подписки).
func subHeaders() map[string]string {
	return map[string]string{
		"profile-title":           subTitleHeader,
		"profile-update-interval": subInterval,
		"subscription-userinfo":   subUserInfo,
		"support-url":             subSupportURL,
		"profile-web-page-url":    subWebPageURL,
	}
}

// subInlineHeaders — те же метаданные, но строками-комментариями в начале тела.
// Так их отдают провайдеры, которые не управляют заголовками ответа;
// parseHeadersFromContent поднимает их в http.Header уже на нашей стороне.
func subInlineHeaders() string {
	var b strings.Builder
	for _, k := range []string{
		"profile-title", "profile-update-interval",
		"subscription-userinfo", "support-url", "profile-web-page-url",
	} {
		fmt.Fprintf(&b, "//%s: %s\n", k, subHeaders()[k])
	}
	return b.String()
}

// fixture читает тело подписки. Вызывать ДО isolateWorkdir — путь относительный.
func fixture(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("testdata", "subscription.txt"))
	if err != nil {
		t.Fatalf("resolve fixture path: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return string(content)
}

// isolateWorkdir уводит артефакты во временный каталог: profile-слой пишет
// data/profiles/<id>.info и leveldb ОТНОСИТЕЛЬНО рабочего каталога
// (profile_repository.go:18, db/inhive_db.go getDB) — без этого каждый прогон
// оставлял базу прямо в дереве исходников.
func isolateWorkdir(t *testing.T) {
	t.Helper()
	t.Chdir(t.TempDir())
}

// serveSubscription поднимает локальный эндпоинт подписки.
func serveSubscription(t *testing.T, body string, headers map[string]string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/sub"
}

// assertSubInfo проверяет разобранные метаданные подписки — единый набор
// ожиданий для обоих путей доставки заголовков.
func assertSubInfo(t *testing.T, entity *profile.ProfileEntity) {
	t.Helper()

	if entity.Name != subTitle {
		t.Errorf("profile title: got %q, want %q", entity.Name, subTitle)
	}
	if entity.SubInfo == nil {
		t.Fatalf("SubInfo не разобран (заголовок subscription-userinfo потерян)")
	}
	info := entity.SubInfo
	if info.Upload != 0 || info.Download != 0 || info.Total != subTotal || info.Expire != subExpire {
		t.Errorf("subscription userinfo разобран неверно: %v", info)
	}
	if info.SupportUrl != subSupportURL {
		t.Errorf("support URL: got %q, want %q", info.SupportUrl, subSupportURL)
	}
	if info.WebPageUrl != subWebPageURL {
		t.Errorf("web page URL: got %q, want %q", info.WebPageUrl, subWebPageURL)
	}
	if entity.Options == nil {
		t.Fatalf("ProfileOptions не разобраны (заголовок profile-update-interval потерян)")
	}
	if got, want := entity.Options.UpdateInterval, int64(24*60*60*1000); got != want {
		t.Errorf("update interval: got %d ms, want %d ms", got, want)
	}
}

// assertStored проверяет, что профиль реально доехал до БД и на диск.
func assertStored(t *testing.T, entity *profile.ProfileEntity) {
	t.Helper()

	stored, err := profile.GetById(entity.Id)
	if err != nil {
		t.Fatalf("профиль не читается из БД: %v", err)
	}
	if stored.Name != entity.Name {
		t.Errorf("имя в БД: got %q, want %q", stored.Name, entity.Name)
	}
	if _, err := os.Stat(filepath.Join("data", "profiles", entity.Id+".info")); err != nil {
		t.Errorf("контент профиля не записан: %v", err)
	}
}

// Метаданные приходят HTTP-заголовками, тело — чистый список share-link'ов.
func TestAddByUrlHeadersFromHTTP(t *testing.T) {
	body := fixture(t)
	isolateWorkdir(t)

	url := serveSubscription(t, body, subHeaders())
	entity, err := profile.AddByUrl(libbox.BaseContext(nil), url, "", false)
	if err != nil {
		t.Fatalf("AddByUrl: %v", err)
	}
	t.Cleanup(func() { _ = profile.DeleteById(entity.Id) })

	assertSubInfo(t, entity)
	assertStored(t, entity)
}

// Метаданные приходят комментариями в теле, заголовков ответа нет вовсе.
func TestAddByUrlHeadersFromContent(t *testing.T) {
	body := subInlineHeaders() + fixture(t)
	isolateWorkdir(t)

	url := serveSubscription(t, body, nil)
	entity, err := profile.AddByUrl(libbox.BaseContext(nil), url, "", false)
	if err != nil {
		t.Fatalf("AddByUrl: %v", err)
	}
	t.Cleanup(func() { _ = profile.DeleteById(entity.Id) })

	assertSubInfo(t, entity)
	assertStored(t, entity)
}

// AddByContent — путь «пользователь вставил конфиг руками», без HTTP вообще.
func TestAddByContent(t *testing.T) {
	body := fixture(t)
	isolateWorkdir(t)

	const name = "Ручная вставка"
	entity, err := profile.AddByContent(libbox.BaseContext(nil), body, name, false)
	if err != nil {
		t.Fatalf("AddByContent: %v", err)
	}
	t.Cleanup(func() { _ = profile.DeleteById(entity.Id) })

	if entity.Name != name {
		t.Errorf("profile name: got %q, want %q", entity.Name, name)
	}
	assertStored(t, entity)
}

// Гард на саму фикстуру: заголовок в ней лежит в base64 (так его шлёт боевой
// сервер), и разъехавшийся literal иначе всплыл бы как невнятный diff имени.
func TestFixtureTitleIsBase64OfExpected(t *testing.T) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(subTitleHeader, "base64:"))
	if err != nil {
		t.Fatalf("profile-title не декодируется из base64: %v", err)
	}
	if string(decoded) != subTitle {
		t.Errorf("decoded title: got %q, want %q", decoded, subTitle)
	}
}
