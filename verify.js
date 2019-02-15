const fs = require('fs');
const crypto = require('crypto');
const { Certificate } = require('pkijs');
const asn1js = require('asn1js');

// 常见ID到算法名的映射
const ALGO_MAPPING = {
  "1.2.840.113549.1.1.2": "RSA-MD2",
  "1.2.840.113549.1.1.4": "RSA-MD5",
  "1.2.840.10040.4.3": "DSA-SHA1",
  "1.2.840.10045.4.1": "ECDSA-SHA1",
  "1.2.840.10045.4.3.2": "ECDSA-SHA256",
  "1.2.840.10045.4.3.3": "ECDSA-SHA384",
  "1.2.840.10045.4.3.4": "ECDSA-SHA512",
  "1.2.840.113549.1.1.10": "RSA-PSS",
  "1.2.840.113549.1.1.5": "RSA-SHA1",
  "1.2.840.113549.1.1.14": "RSA-SHA224",
  "1.2.840.113549.1.1.11": "RSA-SHA256",
  "1.2.840.113549.1.1.12": "RSA-SHA384",
  "1.2.840.113549.1.1.13": "RSA-SHA512"
};

function tryParseBer(binaryData) {
  // macOS导出的DER格式证书
  if (binaryData[0] !== '-'.charCodeAt(0)) {
    return binaryData;
  }
  // Windows导出的PEM格式证书
  const str = binaryData.toString('utf8');
  const base64Pem = str.replace('-----BEGIN CERTIFICATE-----', '').replace('-----END CERTIFICATE-----', '');
  return Buffer.from(base64Pem, 'base64');
}

function parseCert(certPath) {
  const binaryData = fs.readFileSync(certPath);
  const ber = tryParseBer(binaryData);
  const berBuf = Uint8Array.from(ber).buffer;
  const asn1 = asn1js.fromBER(berBuf);
  
  if (asn1.offset === -1) throw new Error('Can not parse binary data as ASN1 format');
  
  const certificate = new Certificate({ schema: asn1.result });
  return certificate;
}

function tryVerify(cert, parentCert) {
  // 真实的证书验证还会验证有效期等其它因素，这里略去
  // 从父证书中读取公钥
  const publicKey = crypto.createPublicKey({
    key: Buffer.from(parentCert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex),
    format: 'der',
    type: 'pkcs1',
  });
  // 从证书中读出签名
  const signature = Buffer.from(cert.signatureValue.valueBlock.valueHex);
  // 签名算法在证书中是通过ID的形式存放的，需要手工映射成nodejs API需要的形式
  const algo = ALGO_MAPPING[cert.signatureAlgorithm.algorithmId];
  const verify = crypto.createVerify(algo);
  // tbs为非公开属性，意思是“to be signed”，表示的是未签名前的数据
  verify.update(Buffer.from(cert.tbs));
  // 验证签名有效性
  const result = verify.verify(publicKey, signature);
  return result;
  
}

if(parseFloat(process.version.slice(1)) < 11.6) {
  console.log('不好意思这段脚本暂时只支持 node v11.6.0 及其以上版本');
  process.exit(1);
}

const leafCert = parseCert('./example-certs/github.com.cer');
const intermidiateCert = parseCert('./example-certs/intermiate.cer');
const rootCert = parseCert('./example-certs/root.cer');

// 校验根证书
const resultC = tryVerify(rootCert, rootCert);
console.log('Verify result for root cert:', resultC);

// 校验中间证书
const resultB = tryVerify(intermidiateCert, rootCert);
console.log('Verify result for intermidiate cert:', resultB);

// 校验最终证书
const resultA = tryVerify(leafCert, intermidiateCert);
console.log('Verify result for leaf cert:', resultA);
