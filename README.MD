Радиус сервер с хранением учетных данных в файле<br>
В файле users указывайте всегда когда это возможно не пароль а его хэш<br>
Например можно так получить хэш<br>
echo -n <пароль> | openssl dgst -binary -sha1 | openssl base64<br>
Пример:<br>
echo -n AdminTest | openssl dgst -binary -sha1 | openssl base64<br>
<hr>
Пример секции:<br>
adminuser SHA-Password := "GYCVM7N9+bQ28pAJYqLQfNL98N0="<br>
        Service-Type = Administrative-User,<br>
        Cisco-AVPair = "shell:priv-lvl=15"<br>
<hr>
Так же можно воспользоваться кодом p2h.go<br>
Им можно получить зашифрованный пароль либо SHA либо SSHA
./p2h -p "пароль" -t "тип шифрования sha или ssha"<br>
Пример:<br>
./p2h -p TestPass -t ssha<br>
SSHA-Password := "QN8QktOYqKxu14eZxOo4MN5KsQPmHcKUuzjkxfQJusopiEMW"