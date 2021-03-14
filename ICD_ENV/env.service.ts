import { Injectable } from '@angular/core';
​
@Injectable({
  providedIn: 'root'
})
export class EnvService {
​
  public dbhost = 'localhost';
  public dbport = 7000;
  public db_service_url = 'http://' + this.dbhost + ':' + this.dbport;
​
  constructor() { }
​
  skip_spinner_for_services = [];
​
}
