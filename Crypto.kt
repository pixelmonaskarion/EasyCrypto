package com.chrissytopher.sharedclipboard

import android.util.Base64
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import kotlin.math.ceil
import kotlin.math.min

data class Keys(val public: String, val private: String)

fun generateKeyPair(): Keys {
    val keyPair = generateRSAKeyPair()
    val publicKey = exportRSAPublicKeyAsString(keyPair.public)
    val privateKey = exportRSAPrivateKeyAsString(keyPair.private)
    return Keys(publicKey, privateKey)
}

fun encrypt(data: String, publicKey: String): String {
    return encryptDataWithRSAPublicKey(data.toByteArray(Charsets.UTF_8), importRSAPublicKeyFromString(publicKey))
}

fun decrypt(data: String, privateKey: String): String {
    return String(decryptDataWithRSAPrivateKey(data, importRSAPrivateKeyFromString(privateKey)), Charsets.UTF_8)
}

fun generateRSAKeyPair(): KeyPair {
    val keyGen = KeyPairGenerator.getInstance("RSA")
    keyGen.initialize(2048)
    return keyGen.generateKeyPair()
}

fun exportRSAPublicKeyAsString(publicKey: PublicKey): String {
    return Base64.encodeToString(publicKey.encoded, Base64.DEFAULT)
}

fun exportRSAPrivateKeyAsString(privateKey: PrivateKey): String {
    return Base64.encodeToString(privateKey.encoded, Base64.DEFAULT)
}

fun importRSAPublicKeyFromString(keyString: String): PublicKey {
    val keyBytes = Base64.decode(keyString, Base64.DEFAULT)
    val keySpec = X509EncodedKeySpec(keyBytes)
    val keyFactory = KeyFactory.getInstance("RSA")
    return keyFactory.generatePublic(keySpec)
}

fun importRSAPrivateKeyFromString(keyString: String): PrivateKey {
    val keyBytes = Base64.decode(keyString, Base64.DEFAULT)
    val keySpec = PKCS8EncodedKeySpec(keyBytes)
    val keyFactory = KeyFactory.getInstance("RSA")
    return keyFactory.generatePrivate(keySpec)
}

fun encryptDataWithRSAPublicKey(dataBytes: ByteArray, publicKey: PublicKey): String {
    val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)
    val blockSize = 190
    var offset = 0
    var encryptedBytes = byteArrayOf()
    while (offset < dataBytes.size) {
        val block = dataBytes.slice(offset until min(offset+blockSize, dataBytes.size)).toByteArray()
        offset += blockSize
        println(block.size)
        encryptedBytes += cipher.doFinal(block)
    }
    return Base64.encodeToString(encryptedBytes, Base64.DEFAULT)
}

fun decryptDataWithRSAPrivateKey(encryptedDataString: String, privateKey: PrivateKey): ByteArray {
    val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
    cipher.init(Cipher.DECRYPT_MODE, privateKey)
    val encryptedData = Base64.decode(encryptedDataString, Base64.DEFAULT)
    val blockSize = cipher.blockSize
    val numBlocks = ceil(encryptedData.size.toDouble() / blockSize.toDouble()).toInt()
    var decryptedBytes = byteArrayOf()
    for (i in 0 until numBlocks) {
        val blockOffset = i * blockSize
        val block = encryptedData.slice(blockOffset until min(blockOffset + blockSize, encryptedData.size)).toByteArray()
        decryptedBytes += cipher.doFinal(block)
    }
    return decryptedBytes
}