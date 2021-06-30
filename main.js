var fs = require('fs');

let file = fs.readFileSync('certificateDor.pem');
let public = fs.readFileSync('public.pem');
let private = fs.readFileSync('private.pem');
const gostCrypto = require('node-gost');
let privateKey; let publickey; let signature;


console.log('Создаем сертификат');
// Создаем самоподписной сертификат с указанными параметрами
var cert = new gostCrypto.cert.X509({
    subject: {
        countryName: "Страна",
        stateOrProvinceName: "Город",
        organizationName: "Организация",
        organizationalUnitName: "Отдел",
        title: "Программист",
        commonName: "ФИО подписующего"
    },
    extensions: {
        keyUsage: ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 
            'dataEncipherment', 'keyAgreement', 'keyCertSign', 'cRLSign'],
        extKeyUsage: ['serverAuth', 'clientAuth', 'codeSigning', 'emailProtection']
    },
    // количество дней, которые сертификат валиден
    days: parseInt('365')
});

//Тест первый - генерируем открытый и закрытый ключ и подписываем ими данные
var data = "Какие-то данные для теста. Подойдет что угодно";
console.log('Данные: ' + data)

const { Certificate, PrivateKey } = require('@fidm/x509');
let certificate = {};
let body; let priv;
//Генерируем сертификат
//TC-512
cert.generate('TC-512').then(function(key) {
    // Output ready private key
    certificate.textContent = key.encode('PEM');
    priv = key.encode('PEM');
    // Sign certificate
    return cert.sign(key);
}).then(function() {
    // Output ready certificate
    body = cert.encode('PEM');
    certificate.textContent = cert.encode('PEM') + '\r\n\r\n' + certificate.textContent;
    return cert.verify();
}).catch(function(reason) {
    console.log(reason.message);
    // alert(reason.message);
}).then(function(){

    let privkey = PrivateKey.fromPEM(priv);
    console.log("Private: " + privkey.keyRaw.toString('hex'));
    let pubkey = Certificate.fromPEM(body).subjectKeyIdentifier;
    console.log("Public: " + pubkey);
    let cert = Certificate.fromPEM(body);

    console.log("Генерируем ключи и с их помощью подписываем данные")
    //Генерируем ключи
    gostCrypto.subtle.generateKey('GOST R 34.10', true, ['sign', 'verify']).then(function(keyPair) {
        //Генерируем закрытый ключ
        gostCrypto.subtle.exportKey('raw', keyPair.privateKey).then(function(result) {
            privateKey = gostCrypto.coding.Hex.encode(result);
            console.log("Приватный ключ"); 
            console.log(privateKey);
            //Генерируем открытый ключ
            gostCrypto.subtle.exportKey('raw', keyPair.publicKey).then(function(result) {
                publicKey = gostCrypto.coding.Hex.encode(result);
                console.log("Открытый ключ");
                console.log(publicKey);
            });

            //Подписываем данные, получая сигнатуру
            gostCrypto.subtle.importKey('raw', gostCrypto.coding.Hex.decode(privateKey),
                    'GOST R 34.10', true, ['sign']).then(function(key) {
                return gostCrypto.subtle.sign('GOST R 34.10/GOST R 34.11', key, 
                    gostCrypto.coding.Chars.decode(data));
            }).then(function(result) {
                console.log('Сигнатура данных: ' + gostCrypto.coding.Hex.encode(result));
                let signature = gostCrypto.coding.Hex.encode(result);

                //Проверяем сообщение с помощью полученной сигнатуры
                gostCrypto.subtle.importKey('raw', gostCrypto.coding.Hex.decode(publicKey),
                        'GOST R 34.10', true, ['verify']).then(function(key) {
                    return gostCrypto.subtle.verify('GOST R 34.10/GOST R 34.11', key, 
                        gostCrypto.coding.Hex.decode(signature), gostCrypto.coding.Chars.decode(data));
                }).then(function(result) {
                    // Получаем результат
                    let verified = result ? 'Да' : 'Нет';
                    console.log("Не изменялись ли данные? " + verified)
                }).catch(function(error) {
                    alert(error.message);
                });

            }).catch(function(error) {
                console.log(error.message);
            });
        });
    }).catch(function(error) {
        console.log(error.message);
    });



});


// //Тест второй. Попытка подписать данными с помощью открытого и закрытого ключа, вытянутого из созданного сертификата. 
// //Впоследствии можно попытаться сделать также с полученным от главстата сертификатом
// console.log('Тест второй')

// certificate = {};
// //Генерируем сертификат
// //TC-512
// cert.generate('TC-512').then(function(key) {
//     // Output ready private key
//     certificate.textContent = key.encode('PEM');
//     priv = key.encode('PEM');
//     // Sign certificate
//     return cert.sign(key);
// }).then(function() {
//     // Output ready certificate
//     body = cert.encode('PEM');
//     certificate.textContent = cert.encode('PEM') + '\r\n\r\n' + certificate.textContent;
//     return cert.verify();
// }).catch(function(reason) {
//     console.log(reason.message);
//     // alert(reason.message);
// }).then(function(){

//     let privkey = PrivateKey.fromPEM(priv);
//     console.log("Private: " + privkey.keyRaw.toString('hex'));
//     let pubkey = Certificate.fromPEM(body).subjectKeyIdentifier;
//     console.log("Public: " + pubkey);
//     let cert = Certificate.fromPEM(body);

//     console.log("Генерируем ключи и с их помощью подписываем данные")
//     //Генерируем ключи
//             //Подписываем данные, получая сигнатуру
//             gostCrypto.subtle.importKey('raw', gostCrypto.coding.Hex.decode(priv),
//                     'GOST R 34.10 12 512', true, ['sign']).then(function(key) {
//                         // Use private key for signing message
//                         console.log('Test1');
//                         return gostCrypto.subtle.sign('GOST R 34.10 12 512/GOST R 34.11', key, 
//                             gostCrypto.coding.Chars.decode(data));
//             }).then(function(result) {
//                 console.log('Test2');
//                 // Send signature with message
//                 console.log('Сигнатура данных: ' + gostCrypto.coding.Hex.encode(result));
//                 let signature = gostCrypto.coding.Hex.encode(result);

//                 //Проверяем сообщение с помощью полученной сигнатуры
//                 // Get public key from trusted source
//                 gostCrypto.subtle.importKey('raw', gostCrypto.coding.Hex.decode(pubkey),
//                         'GOST R 34.10 12 512', true, ['verify']).then(function(key) {
//                             console.log('Test3');
//                     // Use public key for verify message signature
//                     return gostCrypto.subtle.verify('GOST R 34.10 12 512/GOST R 34.11', key, 
//                         gostCrypto.coding.Hex.decode(signature), gostCrypto.coding.Chars.decode(data));
//                 }).then(function(result) {
//                     // Получаем результат
//                     let verified = result ? 'Да' : 'Нет';
//                     console.log("Не изменялись ли данные? " + verified)
//                 }).catch(function(error) {
//                     console.log(error.message);
//                 });

//             }).catch(function(error) {
//                 console.log(error.message);
//             });
//         });






