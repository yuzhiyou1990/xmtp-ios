import Foundation
import LibXMTP
import Web3Core

enum KeyUtilError: Error {
	case invalidContext
	case privateKeyInvalid
	case unknownError
	case signatureFailure
	case signatureParseFailure
	case badArguments
	case parseError
}

enum KeyUtilx {
	static func generatePublicKey(from data: Data) throws -> Data {
		let vec = try LibXMTP.publicKeyFromPrivateKeyK256(privateKeyBytes: data)
		return Data(vec)
	}

	static func recoverPublicKeySHA256(from data: Data, message: Data) throws -> Data {
		return try Data(LibXMTP.recoverPublicKeyK256Sha256(message: message, signature: data))
	}

	static func recoverPublicKeyKeccak256(from data: Data, message: Data) throws -> Data {
        return Data(try LibXMTP.recoverPublicKeyK256Keccak256(message: message, signature: data))
	}
	
	static func sign(message: Data, with privateKey: Data, hashing: Bool) throws -> Data {
        let msgData = hashing ? Util.keccak256(message) : message
        let (_compressedSignature, _) = SECP256K1.signForRecovery(hash: msgData, privateKey: privateKey)
        guard let signature = _compressedSignature else {
            throw KeyUtilError.invalidContext
        }
        let rsData = signature[0..<64]
        var vData = signature[64]
        if vData >= 27 && vData <= 30 {
            vData -= 27
        } else if vData >= 31 && vData <= 34 {
            vData -= 31
        } else if vData >= 35 && vData <= 38 {
            vData -= 35
        }
        return rsData + Data([vData])
	}

	static func generateAddress(from publicKey: Data) -> String {
		return Utilities.publicToAddress(publicKey)!.address
	}
}
