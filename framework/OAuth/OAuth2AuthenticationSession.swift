//
//  OAuth2AuthenticationSession.swift
//  reddift
//
//  Created by KY1VSTAR on 09.01.2019.
//  Copyright © 2019 KY1VSTAR. All rights reserved.
//

import Foundation
import SafariServices
import AuthenticationServices

protocol OAuth2AuthenticationSessionProtocol {
    
    typealias CompletionHandler = (URL?, Error?) -> Void
    
    init(url URL: URL, callbackURLScheme: String?, completionHandler: @escaping CompletionHandler)
    
    @discardableResult
    func start() -> Bool
    
    func cancel()
    
}

@available(iOS 12.0, *)
extension ASWebAuthenticationSession: OAuth2AuthenticationSessionProtocol {}

@available(iOS 11.0, *)
extension SFAuthenticationSession: OAuth2AuthenticationSessionProtocol {}

var OAuth2AuthenticationSession: OAuth2AuthenticationSessionProtocol.Type! = {
    if #available(iOS 12.0, *) {
        return ASWebAuthenticationSession.self
    } else if #available(iOS 11.0, *) {
        return SFAuthenticationSession.self
    }
    return nil
}()
