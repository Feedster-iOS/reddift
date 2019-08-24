//
//  OAuth2Authorizer.swift
//  reddift
//
//  Created by sonson on 2015/04/12.
//  Copyright (c) 2015年 sonson. All rights reserved.
//

import UIKit
import SafariServices

/**
Class for opening OAuth2 authorizing page and handling redirect URL.
This class is used by singleton model.
You must access this class's instance by only OAuth2Authorizer.sharedInstance.
*/
public class OAuth2Authorizer: NSObject, SFSafariViewControllerDelegate {
    private var state = ""
    private var authorizationCompletion: ((Result<OAuth2Token>) -> Void)?
    
    private weak var safariViewController: SFSafariViewController?
    private var authenticationSession: OAuth2AuthenticationSessionProtocol?
    /**
    Singleton model.
    */
    public static let sharedInstance = OAuth2Authorizer()
    
    /**
    Open OAuth2 page to try to authorize with all scopes in Safari.app.
    */
    public func challengeWithAllScopes(byPresenting presentingViewController: UIViewController, completion: @escaping (Result<OAuth2Token>) -> Void) throws {
        do {
            try self.challengeWithScopes(["identity", "edit", "flair", "history", "modconfig", "modflair", "modlog", "modposts", "modwiki", "mysubreddits", "privatemessages", "read", "report", "save", "submit", "subscribe", "vote", "wikiedit", "wikiread"], byPresenting: presentingViewController, completion: completion)
        } catch {
            throw error
        }
    }
    
    /**
    Open OAuth2 page to try to authorize with user specified scopes in Safari.app.
    
    - parameter scopes: Scope you want to get authorizing. You can check all scopes at https://www.reddit.com/dev/api/oauth.
    */
    public func challengeWithScopes(_ scopes: [String], byPresenting presentingViewController: UIViewController, completion: @escaping (Result<OAuth2Token>) -> Void) throws {
        let commaSeparatedScopeString = scopes.joined(separator: ",")
        
        let length = 64
        let mutableData = NSMutableData(length: Int(length))
        if let data = mutableData {
            let a = OpaquePointer(data.mutableBytes)
            let ptr = UnsafeMutablePointer<UInt8>(a)
            let _ = SecRandomCopyBytes(kSecRandomDefault, length, ptr)
            self.state = data.base64EncodedString(options: .endLineWithLineFeed)
            guard let authorizationURL = URL(string:"https://www.reddit.com/api/v1/authorize.compact?client_id=" + Config.sharedInstance.clientID + "&response_type=code&state=" + self.state + "&redirect_uri=" + Config.sharedInstance.redirectURI + "&duration=permanent&scope=" + commaSeparatedScopeString)
                else { throw ReddiftError.canNotCreateURLRequestForOAuth2Page as NSError }
            
            authorizationCompletion = { (result: Result<OAuth2Token>) in
                DispatchQueue.main.async {
                    completion(result)
                }
            }
            
            if #available(iOS 11.0, *) {
                authenticationSession = OAuth2AuthenticationSession.init(url: authorizationURL, callbackURLScheme: Config.sharedInstance.redirectURIScheme, completionHandler: { [weak self] redirectURL, error in
                    guard let `self` = self else { return }
                    
                    if let redirectURL = redirectURL {
                        _ = self.receiveRedirect(redirectURL)
                        return
                    }
                    
                    self.authorizationCompletion?(Result<OAuth2Token>(error: error! as NSError))
                    self.authorizationCompletion = nil
                })
                
                authenticationSession!.start()
            } else {
                let sfc = SFSafariViewController(url: authorizationURL)
                safariViewController = sfc
                sfc.delegate = self
                presentingViewController.present(sfc, animated: true, completion: nil)
            }
        } else {
            throw ReddiftError.canNotAllocateDataToCreateURLForOAuth2 as NSError
        }
    }
    
    /**
    Handle URL object which is returned by OAuth2 page at reddit.com
    
    - parameter url: The URL from passed by reddit.com
    - parameter completion: Callback block is execeuted when the access token has been acquired using URL.
    - returns: Returns if the URL object is parsed correctly.
    */
    public func receiveRedirect(_ url: URL) -> Bool {
        guard let completion = authorizationCompletion, safariViewController != nil || authenticationSession != nil else {
            return false
        }
        
        var parameters: [String:String] = [:]
        let currentState = self.state
        self.state = ""
        if url.scheme == Config.sharedInstance.redirectURIScheme {
            if let temp = URLComponents(url: url, resolvingAgainstBaseURL: true)?.dictionary {
                parameters = temp
            }
        }
        
        if let code = parameters["code"], let state = parameters["state"] {
            safariViewController?.dismiss(animated: true, completion: nil)
            authorizationCompletion = nil
            authenticationSession = nil
            
            if !code.isEmpty && state == currentState {
                do {
                    try OAuth2Token.getOAuth2Token(code, completion: completion)
                    return true
                } catch {
                    print(error)
                    return false
                }
            }
        }
        return false
    }
    
    // MARK: - SFSafariViewControllerDelegate
    public func safariViewControllerDidFinish(_ controller: SFSafariViewController) {
        if let completion = authorizationCompletion {
            authorizationCompletion = nil
            
            let error = NSError(domain: "ua.ky1vstar.reddift", code: -4, userInfo: [NSLocalizedDescriptionKey: "Authorization Cancelled"])
            completion(Result<OAuth2Token>(error: error))
        }
    }
    
}
