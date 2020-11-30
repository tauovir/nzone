from HLCAPP.dbserver.HLC_Data_Helper import HLCDataHelper
from HLCAPP.dbserver.HLC_ORM import *
from HLCAPP.dbserver.flask_app import dbsession
from HLCAPP.coreclasses.individual_provider import IndividualProviderObj
from datetime import datetime
from HLCAPP.dbserver.HLC_utils import OtherClassification
from HLCAPP.coreclasses.core_statics import *
from HLCAPP.core_services.core_service_helper import CoreServicesHelper
from HLCAPP.exceptions_file import *
from HLCAPP.coreclasses.provider_discipline import ProviderDisciplineObj
from HLCAPP.Leggero.Leggero_JSON_Helper import LgReturnJSONV2
from HLCAPP.coreclasses.core_statics import *
from HLCAPP.notification_helper.email_content_extension import EmailContentObjExtend
from HLCAPP.notification_helper.email_verification import EmailVerificationObj
from HLCAPP.coreclasses.user import UserObj
#================
from HLCAPP.coreclasses.biz_org import BizOrgObj

class IndividualProviderServices(CoreServicesHelper):

    def __init__(self):
        super(IndividualProviderServices, self).__init__()
        self.data_helper = HLCDataHelper()
        self.virtal_div_names = [VOICE_DIV, VIDEO_DIV]
        self.dbsession = dbsession
        self.retjson = LgReturnJSONV2()

    def convert_file_payload(self, files):
        data = []
        for _item in files:
            data.append({
                    'document_type': _item['table_name'],
                    'document_name': _item['file_name'],
                    'document_identifier': _item['file_identifier'],
                    'document_data': _item['file_data'].split(',')[1]
                })
        return data

    def get_provider_insert_payload(self, payload):

        personal_details = payload["personal_details"]
        user_details = payload["user_details"]
        provider_details = payload["provider_details"]
        professional_details = payload["professional_details"]
        company_details = payload["practice_details"]
        div_address_details = payload["address_details"]
        other_classification_payload = payload.get('other_classification', [])

        company_details.update({'hlc_platform_role': {BIZ_ORG_KEY: PROVIDER_BIZ}})
        main_div_payload = {'name':IND_PROV_MAIN_DIV_NAME, 'type':{DIV_STATUS_KEY: DIV_ACTIVE,
                                                                   DIV_TYPE_KEY: IND_PROV_MAIN_DIV_TYPE}}


        extra_divs = filter(lambda x: x in self.virtal_div_names, provider_details.get("consultation_type", []))

        main_physical_division = {'name':company_details['company_name'],
                                  'type':{DIV_STATUS_KEY: DIV_ACTIVE, DIV_TYPE_KEY: PHYSICAL_DIV_TYPE}}
        extra_divs_payload = [main_physical_division]
        for _div in extra_divs:
            extra_divs_payload.append({'name':_div,
                                  'type':{DIV_STATUS_KEY: DIV_ACTIVE, DIV_TYPE_KEY: _div}})

        skill_tags = self.serilialize_skills_data(provider_details)
        provider_payload = {
        'is_individual' : True, 'status' : provider_details["status"],'skill_tags' : skill_tags,
        'type': provider_details["provider_type"],'provider_name': personal_details["first_name"] + " " + personal_details["last_name"],
        'longitude' : str(provider_details["long_lat"]['long']),'latitude' : str(provider_details["long_lat"]['lat']),
        'hlc_provider_type' : payload.get('hlc_provider_type', PROV_EXTERNAL)
        }

        user_details.update({'status': 2})
        professional_details_payload = self.serialize_provider_certs_json(professional_details)

        files_uploaded = self.convert_file_payload(payload["files_payload"])

        return provider_payload, company_details, main_div_payload, personal_details, user_details, \
               professional_details_payload, div_address_details, extra_divs_payload, files_uploaded, \
               other_classification_payload

    def create_provider(self, payload):
        # TODO Refresh Views, currently inside create provider service.
        ind_prov_obj = IndividualProviderObj()

        provider_payload, company_details, main_div_payload, personal_details, user_details, \
        professional_details_payload, div_address_details, extra_divs_payload, files_uploaded, \
        other_classification_payload = self.get_provider_insert_payload(payload)

        provider_rec, biz_rec, div_rec, extra_div_recs, person_rec, user_rec,cert_rec = \
                            ind_prov_obj.create_individual_provider(provider_payload, company_details, main_div_payload,
                              personal_details, user_details,professional_details_payload, div_address_details,
                              extra_divs_payload, files_uploaded)

        classification_retdata = {"errCode": 0, "msg": "No other classification."}
        if other_classification_payload:
            classification_obj = OtherClassification()
            classification_retdata = classification_obj.add_new_classification_value(other_classification_payload,
                                                                                     person_rec.id,
                                                                                     commit_flag=False)

        provider_disc = ProviderDisciplineObj()

        provider_disc_payload = {'this_object2provider': provider_rec.id, 'this_object2person': person_rec.id}

        # Todo remove these line when provider_discipline_classification come from frontend
        classification_value_list = payload.get('provider_discipline_classification', self.get_default_classification_value())
        disc_ids = self.dbsession.query(ClassificationExtension.extension2discipline).filter(
            ClassificationExtension.classification_value_id.in_(classification_value_list)
        ).all()

        # disc_ids = self.dbsession.query(ClassificationExtension.extension2discipline).filter(
        #     ClassificationExtension.classification_value_id.in_(payload["provider_discipline_classification"])
        # ).all()
        #

        disc_ids_set = set(disc_ids)
        for i in disc_ids_set:
            provider_disc_payload.update({"this_object2discipline": i[0]})
            provider_disc.create_provider_discipline(provider_disc_payload)
        else:
            # Todo remove this line when discioline come
            provider_disc_payload.update({"this_object2discipline": None})
            provider_disc.create_provider_discipline(provider_disc_payload)

        save_data = ind_prov_obj.save()
        self.send_provider_registration_mail(user_rec.user_name)
        return save_data

    #Todo remove this code when front end send provider_discipline_classification
    def get_default_classification_value(self):
        classification_value = []
        data = self.dbsession.query(ClassificationValue).first()
        classification_value.append(data.id)
        print("========************==============")
        print(classification_value)
        return classification_value




    def create_virtual_clinic(self, payload):
        clinic_type = payload.get('clinic_type', None)
        biz_id = int(payload['biz_id'])
        person_id = int(payload['person_id'])
        # if clinic_type not in self.virtal_div_names or not clinic_type:
        #     return self.send_error(str(InvalidClinicType(clinic_type)))

        #TODO Get provider id from frontend
        provider_rec = self.dbsession.query(Provider).filter(Provider.provider2biz_org == biz_id).first()
        if not provider_rec:
            return self.send_error(str(RecordNotFound(biz_id, 'BizorgObj')))
        ind_prov_obj = IndividualProviderObj(provider_rec.id)
        try:
            retdata = ind_prov_obj.add_virtual_clinic(clinic_type, person_id)
            save_data = ind_prov_obj.save()
        except ClinicAlreadyExists as e:
            return {'errCode':2,'msg':str(e)}
        return save_data

    def deactivate_individual_division(self, division_id, provider_id):
        #TODO Refresh Views
        obj = IndividualProviderObj(provider_id)
        obj.deactivate_division(division_id)
        save_data = obj.save()
        save_data.update({'msg': 'Deactivated Division successfully.'})
        return save_data

    # #=============Add Provider Division================
    def add_provider_division(self, options):
        address_details = options['address_payload']
        division_details = options['division_payload']
        biz_id = int(options['biz_id'])
        person_id = int(options['person_id'])
        obj = IndividualProviderObj()

        parent_div = self.dbsession.query(DivOrg).filter(DivOrg.div_org2biz_org == biz_id,
                                                     DivOrg.div_org2parent_div == None).first()

        div_payload = self._set_division(division_details['division_name'], PHYSICAL_DIV_TYPE,parent_div.id, biz_id)
        try:
            obj.save_provider_division(biz_id, person_id, div_payload, address_details)
            self.dbsession.execute('REFRESH MATERIALIZED VIEW CONCURRENTLY in_use.provider_view;')
            self.dbsession.execute('REFRESH MATERIALIZED VIEW CONCURRENTLY in_use.words;')
            obj.save()
        except Exception as e:
            self.dbsession.rollback()
            return {"errCode": 1, "msg": str(e)}
        return {"errCode": 0, "msg": "Successfully Created New Division."}



    def _set_division(self, name, division_type, parent_div_id=None, bizorg_id=None):

        return {'name': name, 'type':{'status': 'active', 'division_type': division_type},
                              'div_org2parent_div': parent_div_id, 'div_org2biz_org':bizorg_id
        }


    def send_provider_registration_mail(self,user_name):
        ext_data = {"user_name":user_name}
        obj = EmailContentObjExtend(email_content_type='provider_signup')
        print("Mail User:",user_name)
        try:
            obj.fire_notification({
                'NotiUserPersonView': [{
                    'colname': 'email_id',
                    'operator': '==',
                    'value': user_name.strip().lower()
                },
                ]
            }, user_name, extra_data=ext_data, create_token=True)
            return {"errCode": 0, "msg": "Successfully Added notification to queue."}
        except Exception as e:
            return {'errCode': 1, 'msg': 'Email ID not present in database' + str(e)}


    def verify_provider_email(self,payload):
        token = payload.get('token',None)
        status = 2
        if not token:
            return {'errCode': 1, 'msg': 'Token missing'}
        obj = EmailVerificationObj('provider_signup', token)

        if obj._is_token_expired():
            return {'errCode': 1, 'msg': 'Your token expired to verify'}
        try:
            obj.update_token_status(status = 2)
        except TokenAlreadyVerified as e:
            return {'errCode': 1, 'msg': str(e)}

        user_obj = UserObj()
        user_rec = self.dbsession.query(User).filter(User.user_name == obj.email_verification_rec.email_id).first()
        user_obj._user_rec = user_rec
        user_obj.set_status(status=status)
        obj.save()
        return {'errCode': 0, 'msg': 'your email successfully verified'}





if __name__ == '__main__':
    pass
