import { Injectable } from '@angular/core';

@Injectable({
providedIn: 'root'
})
export class EnvService {

public host =  'localhost';
public service_host =  'localhost';
// public host =  '192.168.0.181';
// public service_host =  '192.168.0.181';
public port =  5000;
public service_url =  'http://'+this.host+':'+this.port;
public routes_without_navs = ['/login', '/register', '/ree'];
public sample_file_path = this.service_url + '/download/add_corporate_employee_template/Classication_HLC_v4.xlsx';
//  public address_dropdown_list = [50,51]
public blacklist_file = ['exe','sh'];
public skip_spinner_for_services = [];
public dropdown_list = {
  'city': 51,
  'employement_type': 57,
  'country': 50,
  'province': 52,
  'department': 56,
  'designation' : 62,
  'company': 48,
  'service_provider': 120,
  'document_identifier': 128,
  'professional_body_registration': 126,
  'service_provider_type': 125,
  'provider_certs_dropdown': 128,
  'group_documents_dropdown': 131,
  'division_type': 132,
  'assessment': 134,
  'specialist_type': 135,
  'consultation_type': 127,
  'gender':146,
  'identification_type':149,
  'medical_scheme': 150,
  'provider_skill_tags': 129,
  'nationality': 151,
  'group_category':152,
  'division_type_list': 153,
  'belt_type': 156,
  'marital_status': 157,
  'practice_type': 155,
  'slot_duration':158,
  'consultation_document_identifier':159,
  'speciality_provider_classification_map':160
};

//  public services_to_skip = ['/login', '/register'];
 // RAPTOR
public raptor_db_host = 'localhost'
public raptor_db_port = 5002
public raptor_wh_host = 'localhost'
public raptor_wh_port = 8082
public raptor_db_service_url =  'http://'+this.raptor_db_host+':'+this.raptor_db_port;
public raptor_wh_service_url =  'http://'+this.raptor_wh_host+':'+this.raptor_wh_port;
public ng_serve_port = 4200;
public payment_service_url =  'http://'+this.host+':'+this.ng_serve_port;
public comm_host = 'localhost';
public comm_port = 5001;
public communication_manager_url =  'http://'+this.comm_host+':'+this.comm_port;
public services_to_skip = ['/login', '/register', '/divorg_with_level'];
public member_profiles = ['member','corporate member', 'provider member','super_admin','corporate div admin','corporate admin','corporate member'];
public provider_profiles = ['individual provider','provider div admin','provider admin','provider member'];
public show_file_in_browser = ['pdf','txt','png'];
public paymnet_portal_url = "https://test.oppwa.com/v1/paymentWidgets.js?checkoutId=";

constructor() { }
}

export const COMETCHAT_CONSTANTS = {
  APP_ID: '177947d80d64003',
  REGION: 'US',
  API_KEY: 'c354bcdc14db1e1839296103383ba0e171bf37d5',
  HOST_TYPE: 'local'  // value of Host type should be similar to leggero_config <comet_chat_host_type> value
}