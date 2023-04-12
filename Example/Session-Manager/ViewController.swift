//
//  ViewController.swift
//  Session-Manager
//
//  Created by dhruv@tor.us on 04/12/2023.
//  Copyright (c) 2023 dhruv@tor.us. All rights reserved.
//

import UIKit
import SessionManager

class ViewController: UIViewController {

    var session: SessionManager!
    let sessionID: String = "916212c2194f45f931b08cbb88ac1b3cc1ab6396e047cc02af583a3c6c36584a"

    override func viewDidLoad() {
        super.viewDidLoad()
        session = SessionManager(sessionID: sessionID)
        Task {
            await getSessionData()
        }
        // Do any additional setup after loading the view, typically from a nib.
    }

    func getSessionData() async {
        do {
            let result: SFAModel = try await session.authorizeSession()
            print(result)
        } catch {
            print(error)
        }
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }

}

struct SFAModel: Codable {
    let publicKey: String
    let privateKey: String
}
