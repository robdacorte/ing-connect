import 'dotenv/config';
import * as authService from './services/auth';
export default class ING {
    constructor({clientID}){
        this._clientID = clientID
        authService.getToken(this._clientID)
    }
    
}