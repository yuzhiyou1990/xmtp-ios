//
//  String.swift
//
//
//  Created by Naomi Plasterer on 7/1/24.
//

import Foundation
import CryptoSwift

extension String {
	public var hexToData: Data {
        return Data(hex: self)
	}
}

