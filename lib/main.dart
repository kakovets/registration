import 'package:flutter/material.dart';
import 'dart:io';
import 'dart:typed_data';
import 'dart:developer' as dev;

import 'dart:math';
import 'package:crc32_checksum/crc32_checksum.dart';

import 'package:pointycastle/pointycastle.dart';
// import 'package:pointycastle/api.dart';
// import 'package:pointycastle/asymmetric/api.dart';
import 'package:pointycastle/asymmetric/pkcs1.dart';
import 'package:pointycastle/asymmetric/rsa.dart';
import 'package:pointycastle/block/modes/cbc.dart';


// ignore_for_file: constant_identifier_names
const String NANO_NONE = '\x00';
const String NANO_MAC = '\x01';
const String NANO_NEED_REG = '\x02';
const String NANO_NEED_AES = '\x03';
const String NANO_REG_MAC = '\x04';
const String NANO_AES_KEY = '\x05';
const String NANO_REG_OK = '\x06';
const String NANO_AES_OK = '\x07';
const String NANO_STATUS_PAIRING = '\x08';
const String NANO_SEARCH = '\x09';
const String NANO_I_AM_HEATER = '\x0A';
const String NANO_PING = '\x0B';
const String NANO_SALT = '\x0C';

const String ENCRYPTION_NONE = '\x00';
const String ENCRYPTION_AES = '\x04';
const String ENCRYPTION_RSA = '\x06';

// nano and encryption enums
/*
enum Nano {
  NONE(value: '\x00'),
  MAC(value: '\x01'),
  NEED_REG(value: '\x02'),
  NEED_AES(value: '\x03'),
  REG_MAC(value: '\x04'),
  AES_KEY(value: '\x05'),
  REG_OK(value: '\x06'),
  AES_OK(value: '\x07'),
  STATUS_PAIRING(value: '\x08'),
  SEARCH(value: '\x09'),
  I_AM_HEATER(value: '\x0A'),
  PING(value: '\x0B'),
  SALT(value: '\x0C');

  final String value;
  const Nano({required this.value});
}
enum Encryption {
  NONE(value: '\x00'),
  RSA(value:  '\x04'),
  AES(value:  '\x06');

  final String value;
  const Encryption({required this.value});
}
*/

void main() {
  runApp(const MaterialApp(home: Home()));
}

class Home extends StatefulWidget {
  const Home({Key? key}) : super(key: key);

  @override
  State<Home> createState() => _HomeState();
}

class _HomeState extends State<Home> {
  String aesText = '';
  String aes = '';
  String rsa = '';
  Uint8List key = Uint8List.fromList([]);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(),
      body: Center(
        child: Column(
          children: [
            ElevatedButton(
                onPressed: generateAES,
                child: const Text('AES')
            ),
            ElevatedButton(
                onPressed: generateRSA,
                child: const Text('RSA')
            ),
            Text(aesText),
            Text(rsa),
          ],
        ),
      ),
    );
  }

  void generateAES() {
    final keyParams = KeyParameter(Uint8List(32));
    final secureRandom = SecureRandom('Fortuna'); // Use a cryptographically secure random number generator

    secureRandom.seed(KeyParameter(Uint8List(32))); // Seed the random number generator with secure data
    final random = Random.secure();

    key = keyParams.key;

    for (var i = 0; i < 32; i++) {
      key[i] = random.nextInt(256);
    }

    aes = String.fromCharCodes(key);

    String aesHex = listToHexString(key);
    dev.log('aes(${aes.length}) = $aesHex');

    setState(() {
      aesText = aesHex;
    });
  }

  void generateRSA() {

    Uint8List modulusList = Uint8List.fromList([
      0xb5,0xe7,0xdb,0xdb,0x20,0x29,0x87,0xb9,0x50,0x6d,0x58,0x9b,0x6a,0xa6,0x8f,0x7c,
      0x9e,0xb2,0x51,0xdf,0xb0,0x04,0x3f,0x96,0xa7,0x08,0x05,0x4c,0x1e,0xa7,0xf9,0x7b,
      0x34,0xfd,0x8b,0x6c,0x87,0x98,0x69,0x77,0x4c,0x10,0x77,0xf8,0x5a,0xd4,0x4d,0x6b,
      0xf6,0x8b,0xe0,0xde,0x6a,0xff,0x31,0x94,0xa2,0x91,0xc3,0x83,0x3b,0x7c,0x6c,0x8b,
      0x79,0x76,0xed,0xbc,0x4d,0x61,0xd1,0xb2,0x1c,0xb6,0xdf,0x7d,0xc0,0x76,0x33,0xaf,
      0xd8,0x8e,0xf6,0x9b,0x13,0xb8,0x9c,0xc4,0xf7,0x23,0x7f,0x56,0x11,0xf2,0x26,0xd6,
      0x62,0xd1,0xc2,0x66,0x84,0xf0,0xaa,0xbb,0x5a,0x9b,0x7a,0x44,0x67,0x26,0x88,0x49,
      0xd9,0x83,0x44,0x27,0x8e,0x01,0xf1,0xfc,0x1e,0xb7,0xee,0x7f,0x66,0x63,0x5d,0x61
    ]);

    if (aes.isEmpty) return;

    BigInt modulus = BigInt.zero;
    for (int i = 0; i < modulusList.length; i++) {
      modulus = (modulus << 8) + BigInt.from(modulusList[i]);
    }
    BigInt exponent = BigInt.from(65537);

    String srcMac = '\x00\x00\x00\x00\x00\x00';
    String dstMac = '\xFF\xFF\xFF\xFF\xFF\xFF';

    Random rnd = Random();

    String data = '';
    
    for(int i = 0; i < 8; i++) {
      data += String.fromCharCode(rnd.nextInt(256));
    }

    // TODO hardcoded nano mac
    data += '\x01';
    data += String.fromCharCode(srcMac.length);
    data += srcMac;

    // TODO hardcoded nano aes
    data +='\x05';
    data += String.fromCharCode(aes.length);
    data += aes;

    // to pad when aes Encryption
    /*
    int toPad = 32 - (data.length % 32);

    for(int i = 0; i < toPad; i++) {
      data += String.fromCharCode(rnd.nextInt(256));
    }
    */

    String dataPrint = byteStringToHexString(data);
    dev.log('dataPrint sending(${data.length}) = $dataPrint');

    RSAPublicKey pbKey = RSAPublicKey(modulus, exponent);

    final PKCS1Encoding encrypter = PKCS1Encoding(RSAEngine())
      ..init(true, PublicKeyParameter<RSAPublicKey>(pbKey));

    Uint8List encryptedData = encrypter.process(Uint8List.fromList(data.codeUnits));

    int rndId = rnd.nextInt(0x100000000);

    List<int> littleEndianBytes = [];
    for (int i = 0; i < 4; i++) {
      littleEndianBytes.add((rndId >> (i * 8)) & 0xFF);
    }
    String id = String.fromCharCodes(littleEndianBytes);

    // String id = String.fromCharCode(rndId&0xff)+
    //     String.fromCharCode((rndId>>8)&0xff)+
    //     String.fromCharCode((rndId>>16)&0xff)+
    //     String.fromCharCode((rndId>>24)&0xff);


    // TODO hardcoded encryption and without bit shifting
    String type='\x40';
    type += String.fromCharCode(encryptedData.length);

    String finalMsg =
        srcMac +
        dstMac +
        id +
        type +
        String.fromCharCodes(encryptedData)
    ;
    // plainText += String.fromCharCodes(encryptedData);

    int crc32 = Crc32.calculate(finalMsg.codeUnits);

    for (int i = 0; i < 4; i++) {
      finalMsg += String.fromCharCode(crc32 >> (i * 8) & 0xff);
    }

    // finalMsg += String.fromCharCode(crc32&0xff)+
    //     String.fromCharCode((crc32>>8)&0xff)+
    //     String.fromCharCode((crc32>>16)&0xff)+
    //     String.fromCharCode((crc32>>24)&0xff);


    String readableMsg = byteStringToHexString(finalMsg);
    dev.log('readableMsg(${finalMsg.length}) = $readableMsg');

    // 000000000000
    // FFFFFFFFFFFF
    // CEFE192D
    // 4080
    // 4C4213325202D2BB0AEFA8FDD55D52DE06118B13475E00ADA71239778CB8FBCE
    // F38219CAD60C68D517833D9BE7C0850DA16387CAA14B9D0FFC425C166519F508
    // 55F96E411E65047C624CB3D662DD9F64B8D970628C1AA938B49D3411315106B6
    // 9F72259133E78B5290F471E21079B7ED69E03ABFE460388B4B0C0526E458F215
    // C22B1648

    // Uint8List dataToSend = Uint8List(encryptedData.length + 4);
    // dataToSend.addAll(encryptedData);

    // for (int i = 0; i < encryptedData.length; i++) {
    //   dataToSend[i] = encryptedData[i];
    // }
    // dev.log(String.fromCharCodes(dataToSend));
    //
    // var s = '';
    // for (var unit in dataToSend) {
    //   s += unit.toRadixString(16).padLeft(2, '0').toUpperCase();
    // }
    // dev.log('s = $s');
    // dev.log('crc32 = ${crc32.toRadixString(16)}');
    //
    // dataToSend[encryptedData.length] = crc32&0xff;
    // dataToSend[encryptedData.length+1] = (crc32>>8)&0xff;
    // dataToSend[encryptedData.length+2] = (crc32>>16)&0xff;
    // dataToSend[encryptedData.length+3] = (crc32>>24)&0xff;
    //
    // var k = '';
    // for (var unit in dataToSend) {
    //   k += unit.toRadixString(16).padLeft(2, '0').toUpperCase();
    // }
    // dev.log('k = $k');

    // dataToSend.add((crc32>>8)&0xff);
    // dataToSend.add((crc32>>16)&0xff);
    // dataToSend.add((crc32>>24)&0xff);

    // dataToSend.add(crc32&0xff);
    // dataToSend.add((crc32>>8)&0xff);
    // dataToSend.add((crc32>>16)&0xff);
    // dataToSend.add((crc32>>24)&0xff);

    // encryptedData += String.fromCharCode(crc32&0xff)+
    //     String.fromCharCode((crc32>>8)&0xff)+
    //     String.fromCharCode((crc32>>16)&0xff)+
    //     String.fromCharCode((crc32>>24)&0xff);
    setState(() {
      rsa = readableMsg;
    });
    send(finalMsg, rndId);
  }

  void send(String msg, int rndId) async {
    InternetAddress address = InternetAddress('192.168.1.5');
    // InternetAddress address = InternetAddress('fisherscale.com');
    int port = 7799;
    RawDatagramSocket socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 20002);

    socket.send(msg.codeUnits, address, port);

    listen(socket, rndId);
  }

  void listen(RawDatagramSocket socket, int rndId) {
    socket.listen((event) {
      Datagram? dg = socket.receive();
      if (dg != null) {
        String datagramHex = listToHexString(dg.data);

        dev.log('************   Received   ****************');
        dev.log('${dg.address.address} --- ${dg.port}');
        dev.log(datagramHex);
        dev.log('************   end   ****************');
        dev.log('');

        Uint8List receivedMsg = dg.data;

        if (receivedMsg.length < 6 + 6 + 4 + 2 + 32 + 4) {
          dev.log('UDP: low length\n length = ${receivedMsg.length}',
              error: ErrorDescription('UDP: low length'));
          return;
        }
        if (receivedMsg.length > 1000) {
          dev.log('UDP: big length\n length = ${receivedMsg.length}',
              error: ErrorDescription('UDP: big length'));
          return;
        }

        int calcCrc = Crc32.calculate(receivedMsg.getRange(0, receivedMsg.length - 4));
        List<int> crcRange = receivedMsg.getRange(receivedMsg.length - 4, receivedMsg.length).toList();
        int dataCrc = 0;
        for (int i = crcRange.length - 1; i >= 0; i--) {
          dataCrc = (dataCrc << 8) + crcRange[i];
        }

        if (calcCrc != dataCrc) {
          dev.log('UDP: crc error\n'
              'calcCrc = $calcCrc\n'
              'dataCrc = $dataCrc',
              error: ErrorDescription('UDP: crc error'));
          return;
        }

        List<int> senderMacRange = receivedMsg.getRange(0, 6).toList();
        String senderMac = listToHexString(senderMacRange);

        List<int> deviceMacRange = receivedMsg.getRange(6, 12).toList();
        String deviceMac = String.fromCharCodes(deviceMacRange);

        List<int> idRange = receivedMsg.getRange(12, 16).toList();
        int dataId = 0;
        for (int i = idRange.length - 1; i >= 0; i--) {
          dataId = (dataId << 8) + idRange[i];
        }

        if (dataId != rndId) {
          dev.log('UDP: id error\n'
              'dataId = $dataId\n'
              'rndId  = $rndId',
              error: ErrorDescription('UDP: id error'));
          return;
        }

        int encryption = receivedMsg[16] >> 4;
        dev.log('encryption = ${encryption.toRadixString(16).padLeft(2, '0').toUpperCase()}');

        int dataLength = ((receivedMsg[16] & 0x0f) << 8) + receivedMsg[17];
        dev.log('dataLength = $dataLength');

        List<int> encryptedDataRange = receivedMsg.getRange(18, receivedMsg.length - 4).toList();

        String dataRangePrint = listToHexString(encryptedDataRange);
        dev.log('encryptedDataRange(${dataRangePrint.length ~/ 2}) = $dataRangePrint');

        if (encryptedDataRange.length != dataLength) {
          dev.log('UDP: encryptedDataRange error\n'
              'encryptedDataRange len = ${encryptedDataRange.length}\n'
              'dataLength len = $dataLength',
              error: ErrorDescription('UDP: dataLength error'));
          return;
        }

        final keyParam = KeyParameter(key);
        Uint8List iv = Uint8List.fromList([
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        final params = ParametersWithIV(keyParam, iv);

        CBCBlockCipher cbcBlockCipher = CBCBlockCipher(BlockCipher('AES'))
            ..init(false, params);

        List<int> decryptedData = <int>[];
        for (int i = 0; i < encryptedDataRange.length; i += cbcBlockCipher.blockSize) {
          final block = encryptedDataRange.sublist(i, i + cbcBlockCipher.blockSize);
          final decryptedBlock = cbcBlockCipher.process(Uint8List.fromList(block));
          decryptedData.addAll(decryptedBlock);
        }

        String decryptedDataPrint = listToHexString(decryptedData);
        dev.log('decryptedDataPrint(${decryptedData.length}) = $decryptedDataPrint');

        // to train parse
        /*decryptedData = [];
        var toParse = 'FE,76,96,28,52,FD,1D,E4,01,06,FF,FF,FF,FF,FF,FF,04,06,E4,AB,0F,18,A4,EB,01,06,FF,FF,FF,FF,FF,FF,05,00,00,00,0A,E4,B8,0D,5E,18';
        for (var el in toParse.split(',')) {
          decryptedData.add(int.parse(el, radix: 16));
        }
        dev.log('decr leng = ${decryptedData.length}');
        dev.log(decryptedData.map((e) => e.toRadixString(16)).toString());*/

        int currentIndex = 8;
        while (currentIndex < decryptedData.length) {
          String nano = String.fromCharCode(decryptedData[currentIndex]);
          currentIndex++;
          dev.log('nano = ${nano.codeUnits[0].toRadixString(16)}');

          if (currentIndex >= decryptedData.length) {
            dev.log('current index = $currentIndex,'
                'decryptedData.length = ${decryptedData.length}',
                error: ErrorDescription('End of array reached'));
            break;
          }

          int len = decryptedData[currentIndex];
          currentIndex++;
          dev.log('len = ${len.toRadixString(16)}');

          if (currentIndex + len > decryptedData.length) {
            dev.log('current index + len = ${currentIndex + len},'
                'decryptedData.length = ${decryptedData.length}',
                error: ErrorDescription('Invalid data length'));
            break;
          }

          List<int> info = decryptedData.sublist(currentIndex, currentIndex + len);
          currentIndex += len;

          if (nano == NANO_NONE && len == 0x00) {
            dev.log('end of info');
            break;
          }

          switch (nano) {
            case NANO_MAC:
              dev.log('nano mac');

              String serverMac = '';
              for (var element in info) {
                serverMac += String.fromCharCode(element);
              }

              if (serverMac != '\xFF\xFF\xFF\xFF\xFF\xFF') {
                dev.log('UDP: serverMac error\n'
                    'serverMac = $serverMac',
                    error: ErrorDescription('UDP: serverMac error'));
                return;
              }

            case NANO_REG_MAC:
              dev.log('nano reg mac');

              String userMac = '';
              for (var element in info) {
                userMac += String.fromCharCode(element);
              }

              if (userMac != deviceMac) {
                dev.log('UDP: userMac error\n'
                    'userMac = $userMac\n'
                    'deviceMac = $deviceMac',
                    error: ErrorDescription('UDP: userMac error'));
                return;
              }

            default : dev.log('default');
          }
          dev.log('INFO === ${info.map((e) => e.toRadixString(16).padLeft(2, '0').toUpperCase())}');
          dev.log('INFO === ${listToHexString(info)}');
        }
        // parsing with for
        /*for (int i = 8; i < decryptedData.length; i++) {
          String nano = String.fromCharCode(decryptedData[i]);
          dev.log('nano = ${nano.codeUnits[0].toRadixString(16)}');
          int len = decryptedData[i + 1];
          dev.log('len = ${len.toRadixString(16)}');
          List<int> info = decryptedData.getRange(i + 2, i + 2 + len).toList();

          if (nano == NANO_NONE && len == 0x00) {
            dev.log('end of info');
            return;
          }

          switch (nano) {
            case NANO_MAC:
              dev.log('mac server');

              String serverMac = '';
              for (var element in info) {
                serverMac += String.fromCharCode(element);
              }

              if (serverMac != '\xFF\xFF\xFF\xFF\xFF\xFF') {
                dev.log('UDP: serverMac error', error: ErrorDescription('UDP: serverMac error'));
                dev.log('serverMac = $serverMac');
                return;
              }

            case NANO_REG_MAC:
              dev.log('mac user');

              String userMac = '';
              for (var element in info) {
                userMac += String.fromCharCode(element);
              }

              if (userMac != deviceMac) {
                dev.log('UDP: userMac error', error: ErrorDescription('UDP: userMac error'));
                dev.log('userMac = $userMac');
                dev.log('deviceMac = $deviceMac');
                return;
              }

            default : dev.log('default');
          }
          dev.log('INFO === ${info.map((e) => e.toRadixString(16).padLeft(2, '0').toUpperCase())}');
          i = i + 2 + len - 1;
        }*/
      }
    });
  }

  String listToHexString(List<int> list) {
    String hexString = '';
    for (var unit in list) {
      hexString += unit.toRadixString(16).padLeft(2, '0').toUpperCase();
    }
    return hexString;
  }
  String byteStringToHexString(String str) {
    String hexString = '';
    for (var unit in str.codeUnits) {
      hexString += unit.toRadixString(16).padLeft(2, '0').toUpperCase();
    }
    return hexString;
  }
}
