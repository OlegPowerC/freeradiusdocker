Радиус сервер с хранением учетных данных в файле<br>
В файле users указывайте всегда когда это возможно не пароль а его хэш<br>
Например можно так получить хэш<br>
echo -n <пароль> | openssl dgst -binary -sha1 | openssl base64<br>
Пример:<br>
echo -n AdminTest | openssl dgst -binary -sha1 | openssl base64<br>
<hr>
Пример секции:<br>
adminuser SHA-Password := "GYCVM7N9+bQ28pAJYqLQfNL98N0="
        Service-Type = Administrative-User,
        Cisco-AVPair = "shell:priv-lvl=15"