from HLCAPP.commons.config_reader import LgConfig
import time
from flask_restful import reqparse, abort, Api, Resource
from flask import request
import json
from datetime import datetime, date
from decimal import *
import base64
from sqlalchemy import cast
import HLCAPP.dbserver.handle_employee_div as EH
from HLCAPP.dbserver.document_service import DocumenttHandler
from HLCAPP.dbserver.HLC_Search import SearchHandler as SH
from HLCAPP.dbserver.make_tree import MakeTree, DeleteHerarchy, MakeTreeV2
# from HLCAPP.interface.Send_Mail import EmailHandler
from HLCAPP.interface.encrypt_string import encode_text, decode_text, encode_text_role
from HLCAPP.dbserver.HLC_Handle_Data import AddData
from HLCAPP.dbserver.assessment_handler import AssessmentHandler
# from HLCAPP.dbserver.HLC_Add_corporate_employees import AddEmployeeFromDict
from HLCAPP.dbserver.HLC_Add_Employee_From_Excel import AddEmployeeFromDict
from HLCAPP.dbserver.HLC_Assessment_View_Creator import AnalysisViewCreator
from flask_restful import reqparse, abort, Api, Resource
import json

import HLCAPP.dbserver.handle_multispeciality_div as MH
from HLCAPP.dbserver.handle_group import GroupHandler
# from HLCAPP.dbserver.booking_handler import BookingHandler
from HLCAPP.dbserver.schedule_handler import BookingHandler
from HLCAPP.dbserver.HLC_Rewards_Handler import RewardsHandler
from HLCAPP.dbserver.Peach_Payment import request_payment_details
from HLCAPP.dbserver.Peach_Payment import payment_status
from sqlalchemy import and_, func
import geoalchemy2 as geoalchemy

from flask import request, Response, make_response, jsonify
from flask_app import *
from flask_jwt_extended import *
from datetime import datetime, timedelta
from dateutil.parser import parse
from HLCAPP.dbserver.HLC_Roles import *
from HLCAPP.communication_manager.Send_Mail import EmailHandler
from HLCAPP.dbserver.HLC_Belts_Handler import BeltsHandler
from HLCAPP.dbserver.HLC_utils import DynamicFilter, BreadCrumb, CometChatHelper, OtherClassification
from HLCAPP.dbserver.HLC_Create_Data import DataCreator
from HLCAPP.Report_Generation.calculate_panas_scores import CreatePDFData
from HLCAPP.Report_Generation.calculate_panasold_scores import CreatePDFDataOld
from HLCAPP.Report_Generation.Create_HRA_Report import CreateData
from HLCAPP.Report_Generation.Create_HRA_Workforce_Report import CreateDataHraWorkforce
from HLCAPP.Report_Generation.Create_HRA_Workforce_Report_Official import CreateDataHraWorkforceOffcial
from HLCAPP.Report_Generation.Create_HRA_Glacier_Wealth_Report import CreateDataHraGlacierWealth
from Crypto.Cipher import AES
import base64
from cryptography.fernet import Fernet
from HLCAPP.dbserver.HLC_Engagement_Plan_Handler import EngagementHelper
from HLCAPP.dbserver.HLC_Video_Hanlder import VideoHandler
from HLCAPP.dbserver.HLC_Events_Handler import EventsHandler
from HLCAPP.dbserver.HLC_Profile_Handler import Profile
# from HLCAPP.interface.date_handler import parse_payload
from sqlalchemy.sql import label
from HLCAPP.dbserver.HLC_Table_Preview import TablePreview
from HLCAPP.dbserver.HLC_Inquiry_Handler import InquiryHandler
from HLCAPP.dbserver.HLC_Widgets_Handler import WidgetHandler
from dateutil.parser import parse
from HLCAPP.core_services.booking_services import BookingService
from HLCAPP.core_services.group_services import GroupServices
from HLCAPP.core_services.events_services import EventsService
from HLCAPP.core_services.assessment_services import AssessmentService
from HLCAPP.core_services.engagement_services import EngagementServices
from HLCAPP.data_services.person_data import PersonData

from HLCAPP.core_services.classification_services import ClassificationServices
from HLCAPP.dbserver.classification_service import ClassificationService
from HLCAPP.core_services.token_handler import Token
from HLCAPP.core_services.email_content_service import EmailContentServices
from HLCAPP.core_services.individual_provider_services import IndividualProviderServices
from HLCAPP.dbserver.provider_view_queries import ProviderViewQueries
from HLCAPP.core_services.email_log_service import EmailLogService
from HLCAPP.notification_helper.email_content_extension import EmailContentObjExtend
from HLCAPP.notification_helper.email_verification import EmailVerificationObj

from jwt import ExpiredSignatureError, InvalidTokenError, InvalidAudienceError, InvalidIssuerError, DecodeError

from HLCAPP.core_services.corporate_services import CorporateQueries
from HLCAPP.core_services.provider_services import ProviderViewServices
from HLCAPP.core_services.sms_handler_service import SMSHandler
from HLCAPP.core_services.corporate_customer_services import CorporateCustomerServices
from HLCAPP.data_services.corporate_employee_data import CorporateEmployeeDataService
from HLCAPP.data_services.provider_data_services import ProviderDataServices
from HLCAPP.data_services.multipractitioner_employee import MultiPractEmployeeDataService
from HLCAPP.core_services.user_services import UserService
from HLCAPP.data_services.group_services import GroupDataServices
from HLCAPP.data_services.booking_transaction import BookingTransactionHistory
from HLCAPP.data_services.consultation_services import ConsultationServices
from HLCAPP.core_services.prescription_services import PrescriptionService
from HLCAPP.core_services.discpline_assessment_services import DisciplineAssessmentService
from HLCAPP.core_services.medicine_services import MedicineService
from HLCAPP.core_services.discipline_services import DisciplineService
from HLCAPP.core_services.investigation_services import InvetigationeService
from HLCAPP.data_services.prescription_data_service import PrescriptionDataService


from HLCAPP.dbserver.service_handler_import import *


app.config['JWT_SECRET_KEY'] = \
    '68747470733a2f2f7777772e6c6961766161672e6f72672f456e676c6973682f5348412d47656e657261746f722f484d41432f'
# app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(
#     seconds=int(LC.get('ASIAPP').get('JWT_EXP_DELTA_SECONDS')))

#Setting the expire time to 7 days.
#TODO Make this time changes based on role -> IF app large time, else 8 hours.
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(
    seconds=604800)

app.config['JWT_TOKEN_LOCATION'] = ['headers', 'query_string']

# This option is used to specify what is sent in authorization.If not defined
# defaults to Authorization : Bearer <jwt_token>
app.config['JWT_HEADER_TYPE'] = 'Bearer'

jwt = JWTManager(app)

key = Fernet.generate_key()
cipher_suite = Fernet(key)

# salt = b'!%F=-?Pst970'
# bkey32 = salt.ljust(16)[:16]
# cipher = AES.new(bkey32, AES.MODE_CFB,'This is an IV456')
import flask_restful as restful
from functools import wraps

# Configuration for the routes to restrict access to particalar roles.
routes_config_for_roles = {
    '/update_video': ['super_admin']
}


def get_flask_user_dict():
    return flask.g.u_dict


def role_decorator(func):
    '''
    Decorator function to apply roles for all the API's, uses routes_config_for_roles which defines what roles are
    allowed for which routes. When creating new route, add the route to routes_config_for_roles, and pecify roles data,
    the roles is automatically applied to the selected route.
    :param func:
    :return:
    '''

    @wraps(func)
    def wrapper(*args, **kwargs):
        req_params = request.get_json()
        roles_allowed = routes_config_for_roles.get(request.path, None)
        if request.path in ['/login_v2', '/switch_user_role', '/upload_file', '/divorg_with_level', '/email_log']:
            return func(*args, **kwargs)
        if not req_params.get('hlc_roles_data', None):
            return func(*args, **kwargs)
        current_role_category = json.loads(req_params['hlc_roles_data'])['profile_category']
        if not roles_allowed or current_role_category in roles_allowed:
            return func(*args, **kwargs)
        restful.abort(404)

    return wrapper


allowed_classifications_without_token = [157, 146, 51, 129, 127, 128, 149, 151, 153, 126, 135, 125, 50]

def token_decorator(func):
    '''
    Decorator function to apply roles for all the API's, uses routes_config_for_roles which defines what roles are
    allowed for which routes. When creating new route, add the route to routes_config_for_roles, and pecify roles data,
    the roles is automatically applied to the selected route.
    :param func:
    :return:
    '''

    @wraps(func)
    def wrapper(*args, **kwargs):
        req_params = request.get_json()

        exception_list1 = ['/book_event_for_person', '/handle_event_invitation',
                           '/update_event_invitation', '/update_event_invite_person', '/add_non_members_to_event',
                           '/event_feedback_email',
                           '/get_other_classifications', '/all_internal_provider_locations', '/create_inquiry',
                           '/add_employee_from_outside','/get_corporate_logo','/product/get_product_by_bizorg']

        exception_list2 = ['/add_provider', '/add_member', '/add_employee', '/check_user_email',
                           '/send_registration_email',
                           '/confirm_provider_email', '/send_member_register_mail', '/confirm_member_register_mail',
                           '/reset_password', '/validate_reset_password_token', '/auto_generate_password',
                           '/search_location',
                           '/match_and_populate_address', '/practitioner_location_search', '/link_member_provider',
                           '/get_file',
                           '/get_documents_list', '/add_practitioner', '/get_booking', '/check_practitioner_email',
                           '/send_practitioner_join_request', '/acccept_practitioner_invite', '/get_all_schedule',
                           '/get_practitioner', '/upload_file', '/use_document_service', '/add_employee_from_file',
                           '/update_password',
                           '/email_log', '/push_email_queue', '/v1/get_data_for_cancel_booking', '/v1/cancel_booking',
                           '/confirm_otp', '/resend_otp']

        if request.path in ['/login_v2', '/switch_user_role', '/upload_file',
                            '/divorg_with_level'] + exception_list1 + exception_list2:
            return func(*args, **kwargs)

        if not request.headers.get('Authorization'):
            if request.path == '/get_classification_value_data_dropdown':
                for _rec_id in req_params['classification_type_id']:
                    if _rec_id not in allowed_classifications_without_token:
                        return {"errCode": 90, "msg": "Classification Not Allowed."}
                return func(*args, **kwargs)

        @jwt_required
        def get_user_info_func():
            user_data = get_jwt_identity()
            return user_data

        try:
            user_data = get_user_info_func()
            flask.g.u_dict = user_data
            return func(*args, **kwargs)
        except (ExpiredSignatureError, InvalidTokenError, InvalidAudienceError, InvalidIssuerError, DecodeError) as e:
            return {'errCode': 96, 'msg': "Session expired, please login again "}
        except Exception as e2:
            return {"errCode": 90, "msg": "Some Internal Error", "operror": str(e2)}

    return wrapper


class Resource(restful.Resource):
    '''
    Subclass this class when creating new Resources, the method_decortors accept functions when can be applied to
    all resources, for eg: authentication can be applied to all the resources at once using these method decorators.
    '''
    method_decorators = [role_decorator, token_decorator]


@jwt_required
def token_validation(**kw):
    print kw
    if 'data' in kw:
        if 'hlc_roles_data' in kw['data']:
            kw['data'].pop('hlc_roles_data')
    return True


def token_validation2(**kw):
    print kw
    if 'data' in kw:
        if 'hlc_roles_data' in kw['data']:
            kw['data'].pop('hlc_roles_data')
    return True


@jwt_required
def token_validation_get(**kw):
    return True


class Foo(Resource):

    def post(self):
        data = request.get_json()
        print data
        t = data.get('time', 1)
        time.sleep(t)
        return json.dumps({"msg": "inside foo post"})


class Bar(Resource):

    @jwt_required
    def get(self):
        return json.dumps({"msg": "inside bar get"})


class Search(Resource):

    # @jwt_required
    def post(self):
        data = request.get_json()
        hlc_roles_data = json.loads(data['hlc_roles_data'])
        obj = SH()
        results = obj.search_results(data, hlc_roles_data)
        # obj.hlcsession.close()
        results = {'errCode': 0, "msg": results}
        return results


class SearchProvider(Resource):

    def post(self):
        data = request.get_json()
        # hlc_roles_data = json.loads(data['hlc_roles_data'])
        hlc_roles_data = get_flask_user_dict()  # New way to get roles_data
        obj = SH()
        results = obj.search_provider_internal(data, hlc_roles_data)
        results = {'errCode': 0, "msg": results}
        # obj.hlcsession.close()
        return results


def get_roles_data(user_profile_id):
    sidebar_obj = SideBarParser()
    sidebar_data = sidebar_obj.show_sidebar_data(user_profile_id)
    component_obj = ComponentParser()
    component_json = component_obj.get_component_dict_login(user_profile_id)
    navbar_obj = NavbarParser()
    navbar_json = navbar_obj.get_navbar_data_user(user_profile_id)
    component_json[-1] = navbar_json['msg']
    return sidebar_data, component_json

from HLCAPP.core_services.data_roles.roles_helper import RolesData, User_identifier
from HLCAPP.core_services.data_roles.role_parsers import BizOrgHomeScreenQuery, MultispecHomeScreenQuery

class LoginV2(Resource):

    def __init__(self):
        '''
        Initialize the roles keys map for creating what data can each type of user see.
        Each type of role can have multiple caegories.
        The list of keys given on leaf level determine the data which can be seen by users, the order
        of the keys matters because final roles data map is determined using this list.
        '''

        self.roles_keys = {
            'super_admin': {
                'type1': []
            },
            'member': {
                'type1': ['person_id', 'user_id']
            },
            'individual provider': {
                'type1': ['person_id', 'bizorg_id', 'divorg_id', 'practitioner_id', 'provider_id', 'user_id']
            },
            'corporate': {
                'type1': ['bizorg_id', 'user_id'],
                'type2': ['bizorg_id', 'divorg_id', 'user_id'],
                'type3': ['person_id', 'bizorg_id', 'divorg_id', 'user_id']
            },
            'provider': {
                'type1': ['bizorg_id', 'provider_id', 'user_id'],
                'type2': ['bizorg_id', 'divorg_id', 'practitioner_id', 'provider_id', 'user_id'],
                'type3': ['person_id', 'bizorg_id', 'divorg_id', 'practitioner_id', 'provider_id', 'user_id']
            },
            'app role': {
                'type1': []
            }
        }

        self.roles_func = {
            'person_id': self.create_person_keys,
            'divorg_id': self.create_divorg_keys,
            'bizorg_id': self.create_bizorg_keys,
            'user_id': self.create_user_keys,
            'provider_id': self.empty_func,
            'practitioner_id': self.empty_func
        }

    def empty_func(self, roles_data, userrec, role_category, role_subcategory):
        pass

    def create_person_keys(self, roles_data, userrec, role_category, role_subcategory):
        person_id = userrec['user2person']
        roles_data.update({'person_id': person_id})

    def create_divorg_keys(self, roles_data, userrec, role_category, role_subcategory):
        person_id = userrec['user2person']
        person_biz_org = roles_data['bizorg_id']
        current_divs = 'self' if role_subcategory == 'type3' or role_category == "individual provider" else 'all'
        divorg_map = {'corporate': HlcEmployeeView,
                      'provider': ProviderViewData,
                      'individual provider': ProviderViewData}
        roles_data['divorg_id'] = self.get_divs(person_biz_org, divorg_map[role_category], person_id, current_divs)

    def create_bizorg_keys(self, roles_data, userrec, role_category, role_subcategory):
        person_id = userrec['user2person']
        # Trap any discrepancy using id = -2
        provider_query = dbsession.query(ProviderViewData.bizorg_id,
                                         ProviderViewData.is_individual,
                                         ProviderViewData.provider_id,
                                         ProviderViewData.person_id). \
            filter(ProviderViewData.person_id == person_id)
        if role_category == "corporate":
            person_hlc_rec = dbsession.query(HlcEmployeeView.bizorg_id). \
                filter(HlcEmployeeView.person_id == person_id). \
                first()
            roles_data['bizorg_id'] = person_hlc_rec.bizorg_id if person_hlc_rec else -2
        elif role_category == "provider":
            person_provider_rec = provider_query.first()
            roles_data['bizorg_id'] = person_provider_rec.bizorg_id if person_provider_rec else -2
            roles_data['practitioner_id'] = person_provider_rec.person_id
            roles_data['provider_id'] = person_provider_rec.provider_id
        elif role_category == "individual provider":
            person_provider_rec = provider_query.filter(ProviderViewData.is_individual == True).first()
            roles_data['bizorg_id'] = person_provider_rec.bizorg_id if person_provider_rec else -2
            roles_data['practitioner_id'] = person_provider_rec.person_id
            roles_data['provider_id'] = person_provider_rec.provider_id
        else:
            pass

    def create_user_keys(self, roles_data, userrec, role_category, role_subcategory):
        roles_data.update({'user_id': userrec['user_id']})

    def get_divs(self, bizorg_id, model_name, person_id, current_divs):
        biz_filter = getattr(model_name, 'bizorg_id', -1)
        user_divs = dbsession.query(model_name.bizorg_id, model_name.divorg_id). \
            filter(and_(model_name.bizorg_id == bizorg_id,
                        model_name.person_id == person_id,
                        model_name.person_divorg_status == 1
                        )).all()

        divorg_list = [x[1] for x in user_divs]
        divorg_ids = []
        if current_divs == 'self':
            divorg_ids = divorg_list
        else:
            divorg_data = get_tree_data(bizorg_id)
            tree_data = make_tree(divorg_data, 'div_org2parent_div', 'id', 'name')
            for div in divorg_list:
                divorg_ids.extend([item for item in tree_data.subtree(div).expand_tree()])
            divorg_ids = list(set(divorg_ids))
        return divorg_ids

    def create_user_view_keys(self, userrec, profile_type, category, subcategory, person_validation_key,
                              user_validation_key):
        roles_data = {
            'person_id': -1,
            'bizorg_id': -1,
            'divorg_id': [],
            'practitioner_id': -1,
            'provider_id': -1,
            'profile_name': profile_type,
            'user_id': -1,
            'profile_category': category,
            'profile_subcategory': subcategory,
            'user_profile_id': userrec['user_profile_id']
        }
        role_category = self.roles_keys[category]
        role_subcategory = role_category[subcategory]
        map(lambda x: self.roles_func[x](roles_data, userrec, category, subcategory), role_subcategory)
        roles_data['person_validation_key'] = person_validation_key
        roles_data['user_validation_key'] = user_validation_key
        # roles_data = json.dumps(roles_data)
        # roles_data = encode_text_role(roles_data, data_key_name='roles_data')
        # roles_data = cipher_suite.encrypt(roles_data)
        return roles_data

    def post(self):
        data = request.get_json()
        username = data["email"]
        password = data["password"]

        request_type = data.get('request_type', 'website')
        hlcsession = dbsession

        try:
            userrec = hlcsession.query(UserProfileView). \
                filter(
                and_(UserProfileView.username == str.lower(str(username)), UserProfileView.password == password,
                     UserProfileView.user_profile_status == 1)). \
                order_by(UserProfileView.profile_priority.asc()). \
                all()
        except Exception as e:
            print e
            # hlcsession.close()
            return json.dumps({'errCode': 1, 'msg': 'Could not login'})
        if userrec:
            if userrec[0].status != 2:
                return make_response(json.dumps({'errCode': 1, 'msg': 'Please confirm your account to login'}))
            # print userrec[0].user_id
            start_time = datetime.now() + timedelta(minutes=15)
            user_chat_friends = hlcsession.query(ChatFriends.chat_friends2friend_to). \
                filter(ChatFriends.chat_friends2friend_from == userrec[0].user_id,
                       ChatFriends.chat_end_time > datetime.now(),
                       ChatFriends.chat_start_time < start_time
                       )
            # print user_chat_friends
            user_chat_friends = user_chat_friends.all()

            userrec = [orm_to_dict_v2(item) for item in userrec]
            all_roles = [{'profile': item['profile_name'],
                          'user_profile_id': item['user_profile_id'],
                          'profile_category': item['profile_category'],
                          'profile_subcategory': item['profile_subcategory']}
                         for item in userrec]

            if request_type == 'website':
                user_profile_id = userrec[0]['user_profile_id']
            else:
                user_profile_id = 6

            sidebar_data, component_json = get_roles_data(user_profile_id)

            roles_data = self.create_user_view_keys(userrec[0], all_roles[0]['profile'],
                                                    all_roles[0]['profile_category'],
                                                    all_roles[0]['profile_subcategory'], userrec[0]['user2person'],
                                                    userrec[0]['user_id'])
            # roles_data = {}
            person_id = userrec[0]['user2person']

            person_rec = hlcsession.query(Person).filter(
                Person.id == person_id).first()
            user_email = userrec[0]['username']

            # Get the records for provider id using individual provider, if provider is individual and also sits
            # in a multispecialty, get the provider_id, multispec_id of individual record not the multispecialty
            # record. If practitioner sits in multple multispecialty get the first record, this is in sync when
            # creating the hlc_roles data for provider. Similar assumptions are made for a corporate employee,
            # he cannot be employee of two corporates at once. Since we only return one bizorg_id from here.

            person_provider_rec = hlcsession.query(ProviderViewData.bizorg_id,
                                                   ProviderViewData.is_individual,
                                                   ProviderViewData.provider_id). \
                filter(ProviderViewData.person_id == person_id)
            if all_roles[0]['profile_category'] == "individual provider":
                person_provider_rec = person_provider_rec.filter(ProviderViewData.is_individual == True)
            person_provider_rec = person_provider_rec.first()
            multispec_id = person_provider_rec.bizorg_id if person_provider_rec else -1
            is_individual = person_provider_rec.is_individual if person_provider_rec else None
            provider_id = person_provider_rec.provider_id if person_provider_rec else None
            person_hlc_rec = hlcsession.query(HlcEmployeeView.bizorg_id). \
                filter(HlcEmployeeView.person_id == person_id). \
                first()
            bizorg_id = person_hlc_rec.bizorg_id if person_hlc_rec else -1

            roles_data['rdd'] = RolesData(User_identifier(userrec[0]['user_id'], userrec[0]['user_profile_id'])).get_role_json()
            access_token = create_access_token(identity=roles_data)
            resp = make_response(
                json.dumps({'errCode': 0, 'msg': 'User login succesfull',
                            "token": access_token,
                            "user_id": userrec[0]['user_id'], "multispec_id": multispec_id,
                            "bizorg_id": bizorg_id, 'is_individual': is_individual, 'person_id': person_id,
                            'user_email': user_email, 'person_first_name': person_rec.first_name,
                            'person_last_name': person_rec.last_name,
                            'sidebar_data': sidebar_data,
                            'component_data': component_json,
                            'request_type': request_type,
                            'all_roles': all_roles,
                            'hlc_roles_data': roles_data,
                            'provider_id': provider_id,
                            "user_chat_friends": user_chat_friends,
                            # "force_profile_change":userrec[0]['force_profile_change']
                            }))
            resp.headers.extend({"token": access_token})
        else:
            resp = make_response(
                json.dumps({'errCode': 1, 'msg': 'Invalid Credentials',
                            'request_type': request_type})
            )
        return resp


class GetTree(Resource):

    # @jwt_required
    def post(self):
        data = request.get_json()
        tree_obj = MakeTree()
        tree_data = tree_obj.get_divorg_tree(data)
        # tree_obj.hlcsession.close()
        return tree_data


# @jwt_required
class RemoveDivision(Resource):

    def post(self):
        data = request.get_json()
        divorg_id = int(data['div_id'])
        bizorg_id = int(data['biz_id'])
        delete_div_obj = DeleteHerarchy()
        ret_json = delete_div_obj.deactivate_division(divorg_id, bizorg_id)
        # delete_div_obj.hlcsession.close()
        return ret_json


class GetDivisionEmployees(Resource):

    # Get all employees for a given division, do using json indexing.
    def post(self):
        return []
        # data = request.get_json()
        # # ladb = LeggeroApplicationDB('HLCAPP')
        # # hlcsession = ladb.get_session()
        # hlcsession = dbsession
        # div_id = int(data['div_id'])
        #
        # result = hlcsession.query(HlcEmployeeView). \
        #     filter(and_(
        #     HlcEmployeeView.divorg_id == div_id,
        #     cast(HlcEmployeeView.person_divorg_role["end_date"], String) > datetime.now(
        #     ).strftime('%Y-%m-%dT%H:%M:%S')
        # )).all()
        # # hlcsession.close()
        # if not result:
        #     return []
        # else:
        #     result = [orm_to_dict(item) for item in result]
        #     return result


# @jwt_required
class GetEmployeesDivision(Resource):

    # Get all divisions for a given employee, do using json indexing.
    def post(self):
        data = request.get_json()
        hlcsession = dbsession
        result = hlcsession.query(HlcEmployeeView). \
            filter(and_(
            HlcEmployeeView.person_id == data['person_id'],
            HlcEmployeeView.person_divorg_status == 1
        )).all()
        # final_recs = [orm_to_dict(item) for item in result] if result else []
        final_recs = [orm_to_dict_v2(item) for item in result] if result else []

        return {"errCode": 0, "msg": final_recs}


# @jwt_required
class GetDivorgWithLevel(Resource):

    def post(self):
        data = request.get_json()
        tree_obj = MakeTree()
        divorgs_with_level = tree_obj.get_divorgs_with_level(data)
        # tree_obj.hlcsession.close()
        return divorgs_with_level


# @jwt_required
class GetClassificationTree(Resource):

    def post(self):
        options = request.get_json()
        tree_obj = MakeTree()
        tree_data = tree_obj.make_classification_tree(options)
        # tree_obj.hlcsession.close()
        return tree_data


# @jwt_required
class DeleteClassification(Resource):

    def post(self):
        options = request.get_json()
        classification_id = int(options['class_id'])
        tree_obj = DeleteHerarchy()
        classification_tree = tree_obj.deactivate_classification(
            classification_id)
        # tree_obj.hlcsession.close()
        return classification_tree


class GetClassificationValueDropdown(Resource):

    def post(self):
        data = request.get_json()
        obj = ClassificationService()
        retdata = obj.get_classification_value_dropdown(data)
        return retdata


class GetDivisionsWithPractitioners(Resource):

    def post(self):
        options = request.get_json()
        tree_obj = MakeTree()
        results = tree_obj.divorg_tree_with_practitioners(options)
        # tree_obj.hlcsession.close()
        return results


class SendRegistrationMail(Resource):

    def post(self):
        payload = request.get_json()
        obj = EmailContentObjExtend(email_content_type='registration')
        payload_data = {'token_first_name': payload['first_name'], 'token_last_name': payload['last_name'],
                        'first_name': payload['first_name'], 'last_name': payload['last_name']}
        obj.fire_notification({}, payload['email'].strip().lower(), extra_data=payload_data, create_token=True)
        return {'errCode': 0, 'msg': 'Email sent.'}


class CheckToken(Resource):

    def post(self):
        payload = request.get_json()
        token = payload['token']
        status = str(payload['status'])
        obj = EmailVerificationObj('registration', token)
        try:
            updated_data = orm_to_dict_v2(obj.update_token_status(status))
            user_update = dbsession.query(User).filter(User.user_name == updated_data['email_id'].lower()). \
                update({'status': 2})
            obj.save()
            return {'errCode': 0, 'msg': 'Successfully updated token status', 'email': updated_data['email_id'],
                    'status': status}
        except Exception as e:
            return {'errCode': 1, 'msg': 'Invalid token.', 'err': str(e)}


class SendMemberRegisterMail(Resource):

    def post(self):
        payload = request.get_json()
        hlcsession = dbsession
        # try:
        user_details = hlcsession.query(User).filter(
            User.user_name == payload['email'].strip().lower()).one()
        user_details = orm_to_dict_v2(user_details)
        person_details = hlcsession.query(Person).filter(Person.id == user_details['user2person']).one()
        person_details = orm_to_dict_v2(person_details)
        payload['token'] = encode_text(payload['email'])
        payload.update({'first_name': person_details['first_name'], 'last_name': person_details['last_name']})
        sms_obj = SMSHandler()
        token_handler = Token(hlcsession)
        # sms_handler = SMSHandler(payload['token'], payload['contact_no'])
        if token_handler.store_token(payload, token_type='member_registration'):
            ret_msg = EmailHandler().send_mail.delay('member_sign_up', **payload)
            ret_obj = sms_obj.send_sms(payload['token'], payload['phone_number'])
            return {'errCode': 0, 'msg': 'Email and OTP sent successfully.'}
        else:
            return {'errCode': 1, 'msg': 'Error in storing token'}


class SendMemberRegisterMailV2(Resource):

    def post(self):
        payload = request.get_json()

        obj = EmailContentObjExtend(email_content_type='member_sign_up')
        try:
            obj.fire_notification({
                'NotiMemberSignUpView': [{
                    'colname': 'user_name',
                    'operator': '==',
                    'value': payload['email'].strip().lower()
                }]
            }, payload['email'].strip().lower(), create_token=True)
            return {"errCode": 0, "msg": "Successfuly Added notification to queue."}
        except Exception as e:
            return {'errCode': 1, 'msg': 'Email address not found in database.'}


class PushEmailToQueue(Resource):

    def post(self):
        payload = request.get_json()
        if payload['attachment_email']:
            ret_msg = EmailHandler(payload['data']['email_sender']).send_mail_v2.delay(payload['email_type'],
                                                                                       **payload['data'])
        else:
            ret_msg = EmailHandler(payload['data'].get('email_sender', '')).send_mail.delay(payload['email_type'],
                                                                                            **payload['data'])
        return {"errCode": 0, "msg": "Added Email To Queue."}


class CheckMemberRegistrationToken(Resource):

    def post(self):
        payload = request.get_json()
        token = payload['token']
        status = str(payload['status'])
        obj = EmailVerificationObj('registration', token)
        try:
            updated_data = orm_to_dict_v2(obj.update_token_status(status))
            user_update = dbsession.query(User).filter(User.user_name == updated_data['email_id'].lower()).\
                update({'status': 2})
            obj.save()
            return {'errCode': 0, 'msg': 'Successfully updated token status', 'email': updated_data['email_id'],
                    'status': status}
        except Exception as e:
            return {'errCode': 1, 'msg': 'Invalid token.', 'err': str(e)}


class CheckOtp(Resource):

    def post(self):
        payload = request.get_json()
        email = payload['email']
        otp = payload['otp']
        sms_handler = SMSHandler()
        ret_msg = sms_handler.confirm_otp(email, otp)
        if ret_msg['errCode'] == 0:
            user_update = sms_handler.session.query(User).filter(User.user_name == email.lower()). \
                update({'status': 2})
            sms_handler.save()
        return ret_msg


class ResendOTP(Resource):

    def post(self):
        payload = request.get_json()
        email = payload['email']
        contact_number = payload['phone_number']
        sms_handler = SMSHandler()
        ret_msg = sms_handler.resend_otp(email, contact_number)
        return ret_msg


class ResetPassword(Resource):

    def post(self):
        payload = request.get_json()
        email_id = payload['email']
        obj = EmailContentObjExtend(email_content_type='password_reset')
        try:
            obj.fire_notification({
                'NotiUserPersonView': [{
                    'colname': 'email_id',
                    'operator': '==',
                    'value': email_id
                }]
            }, email_id, create_token=True)
            return {"errCode": 0, "msg": "Successfuly Added notification to queue."}
        except Exception as e:
            return {'errCode': 1, 'msg': 'Email ID not present in database'}


class ValidateResetPassword(Resource):

    def post(self):
        payload = request.get_json()
        token = payload['token']
        status = str(payload['status'])
        obj = EmailVerificationObj('password_reset', token)
        try:
            updated_data = orm_to_dict_v2(obj.update_token_status(status))
            obj.save()
            return {'errCode': 0, 'msg': 'Successfully updated token status', 'email': updated_data['email_id'],
                    'status': status}
        except Exception as e:
            return {'errCode': 1, 'msg': 'Invalid token.', 'err': str(e)}


class UpdatePassword(Resource):
    def post(self):
        payload = request.get_json()
        user_obj = UserService()
        return user_obj.update_password(payload)

class CheckEmail(Resource):

    def post(self):
        options = request.get_json()
        email = options["email"].lower()
        # ladb = LeggeroApplicationDB('HLCAPP')
        # hlcsession = ladb.get_session()

        hlcsession = dbsession

        try:
            # Use joined load when iterating over multiple rows in the returned set
            # userrec = hlcsession.query(User). \
            #     options(joinedload(User.person).
            #             joinedload(Person.providercerts_collection)
            #             ).filter(User.user_name == email). \
            #     first()

            userrec = hlcsession.query(User).filter(
                User.user_name == email).first()

            if userrec:
                person_id = userrec.user2person
                is_provider = True if userrec.person.providercerts_collection else False
                person_data = orm_to_dict(userrec.person)
                person_data = json.dumps(person_data, cls=LgEncoder)
                # hlcsession.close()
                return {"errCode": 0, "msg": True, "person_id": person_id, "is_provider": is_provider,
                        "person_data": person_data}
                # return {}
            else:
                # hlcsession.close()
                return {"errCode": 0, "msg": False}
        except Exception as e:
            # hlcsession.close()
            return json.dumps({"errCode": 1, "msg": str(e)})
        finally:
            pass
            # hlcsession.close()


class SendPassGenEmail(Resource):

    def post(self):
        payload = request.get_json()
        email = payload['email'].lower().strip()
        obj = EmailContentObjExtend(email_content_type='password_auto_generate')
        try:
            obj.fire_notification({
                'NotiUserPersonView': [{
                    'colname': 'email_id',
                    'operator': '==',
                    'value': email
                }]
            }, email, extra_data=payload, create_token=True)
            return {"errCode": 0, "msg": "Successfuly Added notification to queue."}
        except Exception as e:
            return {'errCode': 1, 'msg': 'Email ID not present in database'}


# class AddProvider(Resource):
#
#     def post(self):
#         options = request.get_json()
#         p = AddData()
#         retMsg = p.add_provider(options)
#         # p.hlcsession.close()
#         return retMsg


class AddProvider(Resource):

    def post(self):
        options = request.get_json()
        p = IndividualProviderServices()
        retMsg = p.create_provider(options)
        # p.hlcsession.close()
        return retMsg


class AddMember(Resource):

    def post(self):
        options = request.get_json()
        # SIgnup p call
        p = AddData()
       # retMsg = p.add_member(options)
        #=======Updated code===========
        obj= MemberServices()
        retMsg = obj.add_member(options)
        # p.hlcsession.close()
        return retMsg


class AddEmployeeNonCore(Resource):

    def post(self):
        # return {"errCode": 1, "msg": "Method Not Found."}
        options = request.get_json()
        obj = EH.HandleEmployeeDivs()
        retMsg = obj.add_employee(options)
        # obj.hlcsession.close()
        return retMsg


class AddEmployeeFromOutsideNonCore(Resource):

    def post(self):
        # return {"errCode": 1, "msg": "Method Not Found."}
        options = request.get_json()
        obj = EH.HandleEmployeeDivs()
        retMsg = obj.add_employee_from_outside(options)
        # obj.hlcsession.close()
        return retMsg


# class AddPersonToDivNonCore(Resource):
#     def post(self):
#         # return {"errCode":1, "msg": "Method Not Found."}
#         eh = EH.HandleEmployeeDivs()
#         options = request.get_json()
#         retjson = eh.add_employee_to_div_v4(int(options["div_id"]), int(options["person_id"]),
#                                             int(options["biz_id"]), options["start_date"],
#                                             options["existing_divisions"],
#                                             int(options["employee_id"]))
#         return retjson


# class RemovePersonFromDivNonCore(Resource):
#     def post(self):
#         # return {"errCode": 1, "msg": "Method Not Found."}
#         eh = EH.HandleEmployeeDivs()
#         options = request.get_json()
#         retjson = eh.remove_emp_from_div_v4(int(options["div_id"]), int(options["person_id"]),
#                                             int(options["biz_id"]), options["end_date"], int(options["employee_id"]))
#         return retjson


class LinkMemberProvider(Resource):
    def post(self):
        options = request.get_json()
        p = AddData()
        retMsg = p.link_member(options)
        # p.hlcsession.close()
        return retMsg


# def query_func(query, rolename, kwargs):
#     if rolename == 'super_admin':
#         pass
#     else:
#         query = query.filter_by(**kwargs)
#     return query



# class GetAllEmployees(Resource):
#
#
#     def get_roles_data(self, result, hlcsession):
#         employee_person_ids = [_rec.person_id for _rec in result]
#         employee_roles = hlcsession.query(UserProfileView.user2person, UserProfileView.profile_subcategory). \
#             distinct(UserProfileView.user2person). \
#             filter(UserProfileView.user2person.in_(employee_person_ids),
#                    UserProfileView.profile_category == 'corporate').all()
#         employee_roles_map = {x.user2person: x.profile_subcategory for x in employee_roles}
#         return employee_roles_map
#
#     def post(self):
#         options = request.get_json()
#         biz_id = int(options["biz_id"])
#         div_id = int(options["div_id"])
#         get_roles_data = options.get('get_roles_data', False)
#
#         hlc_roles_data = json.loads(options.get('hlc_roles_data'))
#         df = DynamicFilter()
#         hlcsession = dbsession
#         if div_id == -1:
#             result = hlcsession.query(HlcEmployeeView).distinct(HlcEmployeeView.employee_id). \
#                 filter(HlcEmployeeView.bizorg_id == biz_id,
#                        HlcEmployeeView.employee_active_status == True)
#         else:
#             result = hlcsession.query(HlcEmployeeView). \
#                 filter(and_(
#                 HlcEmployeeView.divorg_id == div_id,
#                 HlcEmployeeView.person_divorg_status == 1
#             ))
#         result = df.filter_result(result, hlc_roles_data)
#         result = result.all()
#         if not result:
#             return {"errCode":0, "msg": []}
#         else:
#             employee_map = self.get_roles_data(result, hlcsession) if get_roles_data else {}
#             result = [orm_to_dict(item) for item in result]
#             for rec in result:
#                 rec['user_profile'] = employee_map.get(rec['person_id'], None) if get_roles_data else None
#                 if parse(rec['person_divorg_role']['end_date']) > datetime.now():
#                     rec['employee_status'] = 'Active'
#                 else:
#                     rec['employee_status'] = 'InActive'
#             return {"errCode":0, "msg": result}

class GetAllEmployees(Resource):
    def post(self):
        options = request.get_json()
        biz_id = int(options["biz_id"])
        div_id = int(options["div_id"])
        get_roles_data = options.get('get_roles_data', False)
        # hlc_roles_data = json.loads(options.get('hlc_roles_data'))
        hlc_roles_data = get_flask_user_dict()
        obj = CorporateQueries()
        retdata = obj.get_all_employees(biz_id, div_id, get_roles_data, hlc_roles_data)
        return retdata


class GetNearestProviders(Resource):

    def post(self):
        options = request.get_json()
        obj = SH()
        results = obj.provider_search_v2(options)
        results = {"errCode": 0, "msg": results}
        return results


class LocationSearch(Resource):

    def post(self):
        options = request.get_json()
        obj = SH()
        results = obj.location_search(options)
        results = {"errCode": 0, "msg": results}
        return results


class MatchAddress(Resource):

    def post(self):
        options = request.get_json()
        obj = SH()
        results = obj.match_location_payload(options)
        results = {"errCode": 0, "msg": results}
        return results


class SearchGroup(Resource):

    def post(self):
        options = request.get_json()
        hlc_roles_data = json.loads(options['hlc_roles_data'])
        obj = SH()
        results = obj.search_group(options, hlc_roles_data)
        results = {"errCode": 0, "msg": results}
        # obj.hlcsession.close()
        return results


class SearchUserFuzzy(Resource):

    def post(self):
        payload = request.get_json()
        obj = SH()
        results = obj.user_search(payload)
        results = {"errCode": 0, "msg": results}
        # obj.hlcsession.close()
        return results


class GetFile(Resource):

    def post(self):
        data = request.get_json()
        # document_type = "person"
        # document_type_id = 2
        document_type = data["document_type"]
        document_type_id = data["document_type_id"]
        document_identifier = data["file_identifier"]
        dh = DocumenttHandler()
        doc_data = dh.get_document(
            document_type, document_type_id, document_identifier)
        # dh.hlcsession.close()
        return doc_data


class GetDocumentsList(Resource):

    def post(self):
        data = request.get_json()
        dh = DocumenttHandler()
        doc_data = dh.get_all_document_names(
            data["document_type"], data["document_type_id"])
        # dh.hlcsession.close()
        return doc_data


class AddScheduleNonCore(Resource):

    def post(self):
        return {"errCode": 1, "msg": "Method Not Found"}
        # data = request.get_json()
        # booking_status = data.get('booking_status', None)
        # bh = BookingHandler()
        # if booking_status:
        #     retJson = bh.add_booking_dummy_rec(data.get('person_id', -1), data.get('division_id', -1),
        #                                        data.get('booking_status', -1), data.get('schedule', {}),
        #                                        data.get('provider_id', -1), data.get('booking_date', None))
        # else:
        #     retJson = bh.add_schedule(data["payload"])
        # # bh.hlcsession.close()
        # return retJson


class AddSchedule(Resource):

    def post(self):
        data = request.get_json()
        booking_status = data.get('booking_status', None)
        obj = BookingService()
        if booking_status:
            retJson = obj.add_dummy_rec(data)
        else:
            retJson = obj.add_schedule(data["payload"])
        return retJson


from HLCAPP.core_services.practitioner_services import PractitionerServices


# class AddPractitioner(Resource):
#
#     def post(self):
#         options = request.get_json()
#         p = MH.HandleMultiSpecialityDivisions()
#         retMsg = p.add_practitioner(options)
#         # p.hlcsession.close()
#         return retMsg

class AddPractitioner(Resource):

    def post(self):
        options = request.get_json()
        p = PractitionerServices()
        retMsg = p.create_practitioner(options)
        return retMsg


class GetAllPractitioner(Resource):
    def post(self):
        options = request.get_json()
        # hlc_roles_data = json.loads(options.get('hlc_roles_data'))
        hlc_roles_data = get_flask_user_dict()  # New way to get roles_data
        pds = ProviderDataServices()
        return pds.get_all_practitioners(options,hlc_roles_data)

class GetPractitionersDivision(Resource):
    def post(self):
        options = request.get_json()
        mle = MultiPractEmployeeDataService()
        return mle.get_practitioner_divisions(options)

class GetIndividualPracTree(Resource):

    def post(self):
        options = request.get_json()
        obj = MakeTreeV2()
        result = obj.get_practitioner_location_tree(options)
        # obj.hlcsession.close()
        return result


class GetPersonInBizOrg(Resource):

    def post(self):
        options = request.get_json()
        biz_id = int(options.get('biz_id'))
        obj = MakeTree()
        person_list = obj.get_employees_in_bizorg(biz_id)
        # obj.hlcsession.close()
        return person_list


class CreateGroup(Resource):

    def post(self):
        options = request.get_json()
        GH = GroupServices()
        response = GH.create_group(options)
        return response


class AllocateGroupToProvider(Resource):

    def post(self):
        options = request.get_json()
        GH = GroupServices()
        response = GH.allocate_group_to_provider(options['group_id'], options['provider_id'])
        return response


class AllocateGroupToPractitioner(Resource):

    def post(self):
        options = request.get_json()
        GH = GroupServices()
        response = GH.allocate_group_to_practitioner(options['group_id'], options['practitioner_id'])
        return response


class AllocateGroupToMultiPractitioner(Resource):

    def post(self):
        options = request.get_json()
        GH = GroupServices()
        response = GH.allocate_group_to_multi_prac(options['group_id'], options['multi_prac_id'])
        return response


class GetPersonInGroup(Resource):
    def post(self):
        options = request.get_json()
        group_id = options['group_id']
        gpr = GroupDataServices()
        return gpr.get_person_in_group(group_id)

class GetPersonInGroupV2(Resource):
    def post(self):
        options = request.get_json()
        group_id = options.get('group_id')
        gpr = GroupDataServices()
        return gpr.get_person_in_group_v2(group_id)

class AddPersonToGroup(Resource):

    def post(self):
        options = request.get_json()
        GH = GroupServices()
        return GH.update_person_in_group(options)


class AddAssessmentToGroup(Resource):

    def post(self):
        options = request.get_json()
        assessment_id = int(options.get('assessment_id'))
        group_id_list = options.get('group_id_list', [])
        created_by = options['person_id']
        end_datetime = options.get('end_datetime', None)
        AH = AssessmentService()
        retdata = AH.allocate_assessment_to_group(assessment_id, group_id_list[0], created_by, end_datetime)
        return retdata


class ExtendAssessmentToPersons(Resource):

    def post(self):
        options = request.get_json()
        assessment_id = int(options.get('assessment_id'))
        assm_group_id = options.get('assessment_group_id')
        event_assessment = options.get('event_assessment')
        person_id_list = options.get('person_id_list', [])
        AH = AssessmentService()
        retdata = AH.extend_assessment_to_persons(assessment_id, assm_group_id, event_assessment, person_id_list)
        return retdata


class AddPractitionerToDivision(Resource):
    def post(self):
        eh = MH.HandleMultiSpecialityDivisions()
        options = request.get_json()
        retjson = eh.add_practitioner_to_div(int(options["div_id"]), int(options["person_id"]),
                                             int(options["biz_id"]
                                                 ), options["start_date"],
                                             options["existing_divisions"])
        # eh.hlcsession.close()
        return retjson


class RemovePractitionerFromDiv(Resource):
    def post(self):
        eh = MH.HandleMultiSpecialityDivisions()
        options = request.get_json()
        retjson = eh.remove_practitioner_from_div(int(options["div_id"]), int(options["person_id"]),
                                                  int(options["biz_id"]), options["end_date"])
        # eh.hlcsession.close()
        return retjson


class GetAllLocations(Resource):

    def post(self):
        options = request.get_json()
        bizorg_id = options["bizorg_id"]
        person_id = options["person_id"]
        division_id = options["div_id"]
        # ladb = LeggeroApplicationDB('HLCAPP')
        # hlcsession = ladb.get_session()
        # TODO Might need to add person_divorg_status==1 for the query. Need to check usage.
        hlcsession = dbsession
        if person_id == -1:
            result = hlcsession.query(ProviderViewData).filter(and_(
                ProviderViewData.bizorg_id == bizorg_id
            )).distinct(ProviderViewData.divorg_id).all()
        elif bizorg_id == -1:
            result = hlcsession.query(ProviderViewData). \
                filter(and_(ProviderViewData.person_id == person_id,
                            ProviderViewData.is_individual == True)).all()
        else:
            result = hlcsession.query(ProviderViewData). \
                filter(ProviderViewData.person_id == person_id, ProviderViewData.bizorg_id == bizorg_id,
                       ProviderViewData.divorg_id == division_id).all()
        # hlcsession.close()
        if result:
            result = [orm_to_dict(item) for item in result]
            return {"errCode": 0, "msg": result, "num_results": len(result)}
        else:
            return {"errCode": 0, "msg": [], "num_results": 0}


class UpdateBookingNonCore(Resource):
    def post(self):
        return {"errCode": 1, "msg": "Method Not Found."}
        # options = request.get_json()
        # person_id = options["practitioner_id"]
        # division_id = options["division_id"]
        # booking_date = options["booking_date"]
        # start_time = options["start_time"]
        # slot_time = options["slot_time"]
        # booker_id = options["person_id"]
        # company_name = options.get('company_name', '')
        # reference_details = options["reference_details"]
        # phone_number = options.get('phone_number', "")
        # obj = BookingHandler()
        # update_data = obj.update_schedule_data_V2(person_id, division_id,
        #                                           booking_date, start_time, slot_time, booker_id,
        #                                           reference_details, company_name, phone_number,
        #                                           options.get('engagement_data', None))
        # # obj.hlcsession.close()
        # return update_data


class UpdateBooking(Resource):
    def post(self):
        options = request.get_json()
        person_id = options["practitioner_id"]
        division_id = options["division_id"]
        booking_date = options["booking_date"]
        start_time = options["start_time"]
        slot_time = options["slot_time"]
        # booker_id = options["person_id"]
        hlc_roles_data = get_flask_user_dict()  # New way to get roles_data
        booker_id = hlc_roles_data['rdd']['person']

        company_name = options.get('company_name', '')
        reference_details = options["reference_details"]
        phone_number = options.get('phone_number', "")
        obj = BookingService()
        update_data = obj.create_booking(person_id, division_id,
                                         booking_date, start_time, slot_time, booker_id,
                                         reference_details, company_name, phone_number,
                                         options.get('engagement_data', None))
        # obj.hlcsession.close()
        return update_data


class GetBooking(Resource):
    def post(self):
        options = request.get_json()
        obj = ScheduleDataServices()
        book_data = obj.get_booking_data(int(options["person_id"]), int(options["division_id"]),
                                         options["booking_date"], options['booking_status'],
                                         options['class_name'])
        return book_data


class GetDataForCancelBooking(Resource):
    def post(self):
        options = request.get_json()
        obj = BookingService()
        book_data = obj.get_data_for_booking_cancel(options['booking_token_data'])
        # obj.hlcsession.close()
        return book_data


class CancelBooking(Resource):
    def post(self):
        options = request.get_json()
        obj = BookingService()
        book_data = obj.cancel_booking(options['booking_token_data'])
        return book_data


class CheckPractitionerEmail(Resource):
    def post(self):
        options = request.get_json()
        multispec_id = options["multispec_id"]
        email = options["email"].lower()
        eh = MH.HandleMultiSpecialityDivisions()
        retjson = eh.check_practitioner_email(multispec_id, email)
        # eh.hlcsession.close()
        return retjson


class SendPractitionerJoinRequest(Resource):

    def post(self):
        payload = request.get_json()
        obj = EmailContentObjExtend(email_content_type='invite_an_existing_provider_to_join_a_multi_specialty')
        payload.update({'token_first_name': payload['provider_first_name'],
                        'token_last_name': payload['provider_first_name'],
                        'token': payload['base64']})
        obj.fire_notification({}, payload['email'].strip().lower(), extra_data=payload, create_token=False)
        return {'errCode': 0, 'msg': 'Email Sent.'}


class AcceptPractitionerInvite(Resource):
    def post(self):
        options = request.get_json()
        bizorg_id = options["bizorg_id"]
        division_id = options["division_id"]
        practitioner_id = options["practitioner_id"]
        start_date = options["start_date"]
        eh = MH.HandleMultiSpecialityDivisions()
        retjson = eh.add_practitioner_to_multispeciality(
            bizorg_id, division_id, practitioner_id, start_date)
        # eh.hlcsession.close()
        return retjson


class GetAllMultispecialty(Resource):

    def post(self):
        options = request.get_json()
        # hlc_roles_data = json.loads(options.get('hlc_roles_data'))
        hlc_roles_data = get_flask_user_dict()  # New way to get roles_data
        obj = ProviderViewServices()
        retdata = obj.get_all_multispecialty(hlc_roles_data)
        return retdata


class GetAllMultispecialtySchedule(Resource):

    def post(self):
        options = request.get_json()
        hlc_roles_data = json.loads(options.get('hlc_roles_data'))
        df = DynamicFilter()
        hlcsession = dbsession
        result = hlcsession.query(ProviderViewData). \
            filter(ProviderViewData.is_individual == False). \
            distinct(ProviderViewData.bizorg_id)
        roles_data = df.get_provider_schedule_roles(hlc_roles_data)
        result = df.filter_result(result, roles_data)
        result = result.all()

        result = [{
            'bizorg_id': item.bizorg_id,
            'company_name': item.company_name,
            'registration_number': item.registration_number,
            'trading_name': item.trading_name
        } for item in result]
        return {"errCode": 0, "msg": result, "num_results": len(result)}


# class AddAssessment(Resource):
#     def post(self):
#         options = request.get_json()
#         obj = AssessmentHandler()
#         retdata = obj.add_assessment(int(options["assessment2practitioner"]), options["assessment2provider"],
#                                      options["name"],
#                                      options["description"], options["questionaire"], options["category"],
#                                      options.get('type', 'nonstandard'), options.get('hlc_role', 'wellness'))
#         # obj.hlcsession.close()
#         return retdata


class AddAssessment(Resource):
    def post(self):
        options = request.get_json()
        obj = AssessmentService()
        retdata = obj.create_assessment(options)
        # obj.hlcsession.close()
        return retdata


class GetAssessment(Resource):
    def post(self):
        options = request.get_json()
        obj = AssessmentHandler()
        retdata = obj.get_assessment(int(options["assessment_id"]))
        # obj.hlcsession.close()
        return retdata


class GetAllAssessment(Resource):
    def post(self):
        options = request.get_json()
        obj = AssessmentHandler()
        columns = options.get('columns', None)
        retdata = obj.get_all_assessment(
            int(options["assessment_id"]), options["assessment_status"], columns)
        # obj.hlcsession.close()
        return retdata


# class CopyAssessment(Resource):
#     def post(self):
#         options = request.get_json()
#         obj = AssessmentHandler()
#         retdata = obj.copy_assessment(int(options["assessment_id"]))
#         # obj.hlcsession.close()
#         return retdata


class CopyAssessment(Resource):
    def post(self):
        options = request.get_json()
        obj = AssessmentService()
        retdata = obj.copy_assessment(int(options["assessment_id"]))
        return retdata


class GetAssessmentData(Resource):
    def post(self):
        payload = request.get_json()
        hlc_roles_data = json.loads(payload.get('hlc_roles_data'))
        ah = AssessmentHandler()
        retdata = ah.get_assessments_bulk(payload['status'],
                                          hlc_roles_data)
        return retdata


# class PublishAssessment(Resource):
#     def post(self):
#         options = request.get_json()
#         obj = AssessmentHandler()
#         retdata = obj.pusblish_assessment(int(options["assessment_id"]))
#         # obj.hlcsession.close()
#         return retdata


class GetGroups(Resource):
    def post(self):
        options = request.get_json()
        obj = GroupHandler()
        retjson = obj.get_all_groups(options)
        # obj.hlcsession.close()
        return retjson


class GetAllSchedule(Resource):
    def post(self):
        options = request.get_json()
        person_id = options["person_id"]
        division_id = options["division_id"]
        booking_status = options["booking_status"]
        obj = BookingHandler()
        book_data = obj.get_all_schedule(
            person_id, division_id, booking_status)
        # obj.hlcsession.close()
        return book_data


class GetAttemptedAnswerCount(Resource):
    def post(self):
        # options = request.get_json()
        # obj = AssessmentHandler()
        # retdata = obj.get_answer_count(int(options["assessment_id"]), int(options['assessment_group_id']))
        # obj.hlcsession.close()
        retdata = {"errCode": 0, "num_persons": 0, "num_questions_list": [], "msg": "API Removed"}
        return retdata


class CheckAttemptedStatus(Resource):
    def post(self):
        options = request.get_json()
        obj = AssessmentHandler()
        retdata = obj.check_assessment_attempted(
            int(options["assessment_id"]), int(options["person_id"]), int(options['assessment_group_id']),
            options['assessment_attempt_type'])
        # obj.hlcsession.close()
        return retdata


# class ChangeAssessmentAnswerStatus(Resource):
#     def post(self):
#         options = request.get_json()
#         obj = AssessmentHandler()
#         retdata = obj.change_assessment_status_1(int(options["person_id"]), int(options["assessment_id"]),
#                                                  int(options["status"]), options['assessment_group_id'],
#                                                  options.get('engagement_data', None),
#                                                  options['assessment_attempt_type'])
#         # obj.hlcsession.close()
#         return retdata


class ChangeAssessmentAnswerStatus(Resource):
    def post(self):
        options = request.get_json()
        obj = AssessmentService()
        retdata = obj.submit_assessment(int(options["person_id"]), int(options["assessment_id"]),
                                        int(options["status"]), options['assessment_group_id'],
                                        options.get('engagement_data', None),
                                        options['assessment_attempt_type'])
        return retdata


class ViewAssessmentAnswersData(Resource):
    def post(self):
        options = request.get_json()
        obj = AssessmentHandler()
        retdata = obj.view_assessment_answers(
            int(options["assessment_id"]), int(options["person_id"]), options['assessment_group_id'])
        # obj.hlcsession.close()
        return retdata


# class UseAssessment(Resource):
#     def post(self):
#         options = request.get_json()
#         obj = AssessmentHandler()
#         retdata = obj.use_assessment(int(options["assessment_id"]))
#         # obj.hlcsession.close()
#         return retdata


class UseAssessment(Resource):
    def post(self):
        options = request.get_json()
        obj = AssessmentService()
        retdata = obj.use_assessment(int(options["assessment_id"]))
        return retdata


class GetPractitioner(Resource):
    def post(self):
        options = request.get_json()
        biz_id = int(options["biz_id"])
        div_id = int(options["div_id"])
        person_id = int(options["person_id"])
        # ladb = LeggeroApplicationDB('HLCAPP')
        # hlcsession = ladb.get_session()
        hlcsession = dbsession

        if div_id == -1:
            result = hlcsession.query(ProviderViewData). \
                filter(and_(
                ProviderViewData.bizorg_id == biz_id,
                ProviderViewData.person_id == person_id
            )).all()
        else:
            # result = hlcsession.query(ProviderViewData). \
            #     filter(and_(
            #     ProviderViewData.divorg_id == div_id,
            #     ProviderViewData.person_divorg_role["end_date"].astext > datetime.now(
            #     ).strftime('%Y-%m-%dT%H:%M:%S'),
            #     ProviderViewData.person_id == person_id
            # )).all()

            result = hlcsession.query(ProviderViewData). \
                filter(and_(
                ProviderViewData.divorg_id == div_id,
                ProviderViewData.person_divorg_status == 1,
                ProviderViewData.person_id == person_id
            )).all()

        # hlcsession.close()
        if not result:
            return {"errCode": 0, "msg": []}
        else:
            results = [orm_to_dict(item) for item in result]
            return {"errCode": 0, "msg": results}


# class AddSchduleSlotsRec(Resource):
#
#     def post(self):
#         data = request.get_json()
#         schedule_data = data["schedule"]
#         person_id = data["person_id"]
#         division_id = data["division_id"]
#         provider_id = data["provider_id"]
#         booking_date = data["booking_date"]
#         booking_status = data["booking_status"]
#         bh = BookingHandler()
#         retJson = bh.add_booking_dummy_rec(person_id, division_id, booking_status, schedule_data, provider_id,
#                                            booking_date)
#         # bh.hlcsession.close()
#         return retJson


class GetPersonData(Resource):
    def post(self):
        data = request.get_json()
        booking_id_list = data.get('booking_id_list')
        # _ladb = LeggeroApplicationDB('HLCAPP')
        # hlcsession = _ladb.get_session()
        hlcsession = dbsession

        person_list = hlcsession.query(BookingTransaction.booking_for_person, BookingTransaction.booking_meta,
                                       BookingTransaction.status, BookingTransaction.id).filter(
            BookingTransaction.id.in_(booking_id_list)).all()
        person_data = hlcsession.query(Person.id, Person.first_name, Person.middle_name, Person.last_name,
                                       Person.national_id, Person.identification_type).filter(
            Person.id.in_([item[0] for item in person_list])).all()
        # hlcsession.close()
        person_data = [{'person_id': item[0], 'first_name': item[1], 'middle_name': item[2], 'last_name': item[3],
                        'national_id': item[4], 'identification_type': item[5], 'metadata': metadata[1],
                        'status': metadata[2], 'id': metadata[3]}
                       for item, metadata in zip(person_data, person_list)]

        return {"errCode": 0, "msg": person_data}


# class SaveAssessment(Resource):
#     def post(self):
#         options = request.get_json()
#         obj = AssessmentHandler()
#         retdata = obj.save_assessment(int(options["person_id"]), options["assessment_answers"],
#                                       int(options["questionaire_id"]), int(
#                 options["status"]),
#                                       options["answers_metadata"], options['assessment_group_id'],
#                                       options.get('engagement_data', None), options['assessment_attempt_type'])
#         # obj.hlcsession.close()
#         return retdata

# TODO Use new service.
class SaveAssessment(Resource):
    def post(self):
        options = request.get_json()
        obj = AssessmentService()
        retdata = obj.attempt_assessment(int(options["person_id"]), options["assessment_answers"],
                                         int(options["questionaire_id"]), int(options["status"]),
                                         options["answers_metadata"], options['assessment_group_id'],
                                         options.get('engagement_data', None), options['assessment_attempt_type'])
        return retdata


class GetAssessmentReport(Resource):
    def post(self):
        options = request.get_json()
        obj = AssessmentHandler()
        retdata = obj.get_report(
            int(options["assessment_id"]), int(options["person_id"]), options['assessment_group_id'])
        # obj.hlcsession.close()
        return retdata


class GetMembers(Resource):
    def post(self):
        options = request.get_json()
        member_list = options.get("member_list", [])
        # ladb = LeggeroApplicationDB('HLCAPP')
        # hlcsession = ladb.get_session()
        hlcsession = dbsession

        if member_list:
            results = []
        else:
            results = hlcsession.query(MemberView).all()
            results = [orm_to_dict_v2(item) for item in results]
        # hlcsession.close()
        return {"errCode": 0, "msg": results}


LC = LgConfig().getConfig()
temporary_download_dir = LC.get('HLCVARS', None).get(
    'temporaryDownloadFolder', None)


class UploadFile(Resource):
    def post(self):
        csvfile = request.files['file']
        document_name = csvfile.filename
        date_time = datetime.now().strftime("%Y_%m_%d-%H:%M:%S")
        document_data = csvfile.read()

        with open(temporary_download_dir + "/" + document_name, "w") as f:
            f.write(document_data)
        return {"errCode": 0, "msg": "Written file Successfully", "path": temporary_download_dir + "/" + document_name,
                "document_name": document_name}


class UseDocumentService(Resource):
    def post(self):

        options = request.get_json()
        filepath = options['filepath']
        document_type = options['document_type']
        document_id = options['document_type_id']
        document_identifier = options['document_identifier']
        document_name = options['document_name']

        try:
            with open(filepath, "r") as f:
                data = f.read()
            document_data_base64 = base64.b64encode(data)

            dh = DocumenttHandler()
            doc_result = dh.store_data(document_name, document_type, document_id, document_identifier,
                                       document_data_base64)
        except Exception as e:
            print e
            return {"errCode": 1, "msg": str(e)}
        return {"errCode": 0, "msg": "Succeffuly entered document into database."}


class AddEmployeeFromFile(Resource):

    def post(self):
        options = request.get_json()
        div_id = int(options['document_type_id'])
        document_type = options['document_type']
        biz_id = int(options['biz_id'])
        add_emp_obj = AddEmployeeFromDict()
        dh = DocumenttHandler()
        file_data = dh.get_all_document_names(document_type, div_id)
        ret_json = add_emp_obj.insert_person_data(
            div_id, biz_id, file_data['doc_data'][0]['document_path'])
        return ret_json


class GetAllClassificationType(Resource):

    def post(self):
        options = request.get_json()
        classfication_type = options.get('classification_type', -1)
        # ladb = LeggeroApplicationDB('HLCAPP')
        # hlcsession = ladb.get_session()

        hlcsession = dbsession

        if classfication_type == -1:
            result = hlcsession.query(ClassificationType).all()
            result = [orm_to_dict_v2(item) for item in result]
            result = sorted(result, key=lambda x: x['name'])
        else:
            result = []
        # hlcsession.close()
        return {"errCode": 0, "msg": result}


class AddSubclassification(Resource):

    def post(self):
        options = request.get_json()
        obj = ClassificationServices()
        result = obj.create_classification_value(options)
        return {"errCode": 0, "msg": result}


class GetClassificationValueRecord(Resource):

    def post(self):
        options = request.get_json()
        obj = ClassificationServices()
        result = obj.get_classification_value_record(options)
        return {"errCode": 0, "msg": result}


class AssessmentProviderBookingDetails(Resource):

    def post(self):
        options = request.get_json()
        obj = AssessmentService()
        result = obj.get_assessment_provider_booking_details(options)
        return {"errCode": 0, "msg": result}


class CreateClassificationType(Resource):

    def post(self):
        options = request.get_json()
        obj = ClassificationServices()
        result = obj.create_classification_type(options)
        return {"errCode": 0, "msg": result}


class UpdateAllowOther(Resource):

    def post(self):
        options = request.get_json()
        obj = ClassificationServices()
        result = obj.update_allow_other(options)
        return {"errCode": 0, "msg": result}


class UpdateProviderDetails(Resource):

    def post(self):
        options = request.get_json()
        p = AddData()
        retMsg = p.update_provider(options)
        # p.hlcsession.close()
        return retMsg


# class DeactivateIndividualDivision(Resource):
#
#     def post(self):
#         options = request.get_json()
#         division_id = options['div_id']
#         provider_id = options['provider_id']
#         p = AddData()
#         retMsg = p.deactivate_individual_division(division_id, provider_id)
#         # p.hlcsession.close()
#         return retMsg


class DeactivateIndividualDivision(Resource):

    def post(self):
        options = request.get_json()
        p = IndividualProviderServices()
        retMsg = p.deactivate_individual_division(options['div_id'], options['provider_id'])
        return retMsg


class GetAllIndividualProvider(Resource):
    '''
    Get All Individual Providers, with only main divisions.
    '''

    def get_event_providers(self, session, event_id, provider_data):
        event_providers = session.query(EventsCreators.events_creator2provider). \
            filter(EventsCreators.events_creators2events == event_id, EventsCreators.status == 1).all()
        event_providers_list = [rec[0] for rec in event_providers]
        for provider in provider_data:
            if provider['provider_id'] in event_providers_list:
                provider['status'] = 1
            else:
                provider['status'] = 0
        return provider_data

    def post(self):
        options = request.get_json()
        provider_status = options.get('status', None)
        event_id = options.get('event_id')
        # hlc_roles_data = json.loads(options.get('hlc_roles_data'))
        hlc_roles_data = get_flask_user_dict()  # New way to get roles_data
        df = DynamicFilter()

        hlcsession = dbsession
        provider_data = hlcsession.query(ProviderViewData).filter(ProviderViewData.is_individual == True,
                                                                  ProviderViewData.divorg_meta[
                                                                      'division_type'].astext == 'Main Division')
        if provider_status != None:
            provider_data = provider_data.filter(ProviderViewData.provider_status == provider_status)
        provider_data = df.filter_result(provider_data, hlc_roles_data)
        provider_data = provider_data.all()
        # hlcsession.close()
        provider_data = [orm_to_dict_v2(item) for item in provider_data]
        if event_id:
            provider_data = self.get_event_providers(hlcsession, event_id, provider_data)
        return {"errCode": 0, "msg": provider_data}


class AddProviderDivision(Resource):

    def post(self):
        options = request.get_json()
        p = AddData()
        # retMsg = p.add_provider_division(options)
        #==================
        obj1 = IndividualProviderServices()
        retMsg = obj1.add_provider_division(options)
        #==========================End ==============
        # p.hlcsession.close()
        return retMsg


class UpdatePractitionerDetails(Resource):

    def post(self):
        options = request.get_json()
        # p = AddData()
        p = MH.HandleMultiSpecialityDivisions()
        retMsg = p.update_practitioner_details(options)
        # p.hlcsession.close()
        return retMsg


class GetBookingValidation(Resource):

    def post(self):
        options = request.get_json()
        practitioner_id = options.get('practitioner_id')
        booking_date = options.get('booking_date', "2000-01-01")
        print booking_date
        bh = BookingHandler()
        retMsg = bh.get_practitioner_schedule_validation(practitioner_id, booking_date,
                                                         options.get('booking_status', [1, 3]))
        # bh.hlcsession.close()
        return retMsg


class CreateVirtualClinic(Resource):

    def post(self):
        options = request.get_json()
        p = AddData()
        # retMsg = p.add_virtual_clinic(options)
        # ==================
        obj1 = IndividualProviderServices()
        retMsg = obj1.create_virtual_clinic(options)
        # ==========================End ==============
        # p.hlcsession.close()
        return retMsg


class BlockSlotNonCore(Resource):
    def post(self):
        return {"errCode": 1, "msg": "Method Not found."}
        # options = request.get_json()
        # person_id = options["practitioner_id"]
        # division_id = options["division_id"]
        # booking_date = options["booking_date"]
        # start_time = options["start_time"]
        # slot_time = options["slot_time"]
        # booker_id = options["person_id"]
        # obj = BookingHandler()
        # update_data = obj.block_slot(person_id, division_id,
        #                              booking_date, start_time, slot_time, booker_id, options.get('block_type', 'block'))
        # # obj.hlcsession.close()
        # return update_data


class BlockSlot(Resource):
    def post(self):
        options = request.get_json()
        person_id = options["practitioner_id"]
        division_id = options["division_id"]
        booking_date = options["booking_date"]
        start_time = options["start_time"]
        slot_time = options["slot_time"]
        booker_id = options["person_id"]
        obj = BookingService()
        update_data = obj.block_slot(person_id, division_id,
                                     booking_date, start_time, slot_time, booker_id, options.get('block_type', 'block'))
        # obj.hlcsession.close()
        return update_data


class GetRoles(Resource):

    def post(self):
        # options = request.get_json()
        roles_obj = UserRoles()
        retdata = roles_obj.get_all_roles()
        # roles_obj.hlcsession.close()
        return retdata


class CreateRole(Resource):

    def post(self):
        options = request.get_json()
        roles_obj = UserRoles()
        retdata = roles_obj.create_new_role(options)
        # roles_obj.hlcsession.close()
        return retdata


class GetSidebar(Resource):

    def post(self):
        options = request.get_json()
        obj = SideBarParser()
        retdata = obj.get_sidebar_data_user(options['profile_id'])
        # obj.hlcsession.close()
        return retdata


class UpdateSidebar(Resource):

    def post(self):
        options = request.get_json()
        obj = SideBarParser()
        retdata = obj.update_sidebar_data(options['sidebar_data'], options['user_profile_id'])
        # obj.hlcsession.close()
        return retdata


class GetComponents(Resource):

    def post(self):
        options = request.get_json()
        obj = ComponentParser()
        retdata = obj.get_component_data_user(user_profile_id=options['user_profile_id'])
        retdata = {"errCode": 0, "msg": retdata}
        # obj.hlcsession.close()
        return retdata


class UpdateComponentsData(Resource):

    def post(self):
        options = request.get_json()
        obj = ComponentParser()
        retdata = obj.update_component_data(int(options['user_profile_id']), options['components_json'])
        # obj.hlcsession.close()
        return retdata


class AddDashboardToAssessment(Resource):

    def post(self):
        options = request.get_json()
        obj = AssessmentHandler()
        retdata = obj.add_dashboard_to_assessment(options['assessment_group_id'], options['dashboard_id'])
        return retdata


class RefreshMatView(Resource):

    def post(self):
        payload = request.get_json()
        assessment_group_id = payload['assessment_group_id']
        obj = AnalysisViewCreator()
        return obj.refresh_mat_view(assessment_group_id)


class GetLoyaltyAudit(Resource):

    def post(self):
        options = request.get_json()
        rw = RewardsHandler()
        retdata = rw.get_user_rewards_audit(options['loyality_audit_user_id'])
        return retdata


class GetNavbarData(Resource):

    def post(self):
        options = request.get_json()
        obj = NavbarParser()
        navbar_json = obj.get_navbar_data(options['profile_id'])
        navbar_json = {"errCode": 0, "msg": navbar_json}
        # obj.hlcsession.close()
        return navbar_json


class UpdateNavbarData(Resource):

    def post(self):
        options = request.get_json()
        obj = NavbarParser()
        navbar_json = obj.update_navbar_data(options['navbar_json'], int(options['profile_id']))
        # obj.hlcsession.close()
        return navbar_json


class GetPaymentDetails(Resource):

    def post(self):
        options = request.get_json()
        amount = options['price']
        currency = options['currency']
        responseData = request_payment_details(amount, currency)
        responseData = {"errCode": 0, "msg": responseData}
        return responseData


class GetPaymentStatus(Resource):

    def post(self):
        payload = request.get_json()
        id = payload['id']
        responseData = payment_status(id)
        responseData = {"errCode": 0, "msg": responseData}
        return responseData


class CreateAnalyticsView(Resource):

    def post(self):
        options = request.get_json()
        assessment_obj = AssessmentHandler()
        retdata = assessment_obj.create_refresh_analytics_view(options['assessment_group_id'],
                                                               options['assessment_type'])
        # assessment_obj.hlcsession.close()
        return retdata


class CreateAutomaticDashboard(Resource):

    def post(self):
        options = request.get_json()
        assessment_obj = AssessmentHandler()
        retdata = assessment_obj.create_dashboard_helper(options['dashboard_id'], options['assessment_group_id'])
        # assessment_obj.hlcsession.close()
        return retdata


class CreateUpdateBelt(Resource):

    def post(self):
        options = request.get_json()
        bh = BeltsHandler()
        retdata = bh.create_update_belt(options['case'], options['belt_name'],
                                        options['belt_type'], options['belt_id'],
                                        options['points'])
        # bh.hlcsession.close()
        return retdata


class SwitchUserRole(Resource):

    def post(self):
        options = request.get_json()
        print options
        hlc_roles_data = json.loads(options['hlc_roles_data'])
        user_profile_id = options['user_profile_id']
        sidebar_data, component_json = get_roles_data(user_profile_id)
        user_roles_keys = LoginV2().create_user_view_keys({'user2person': hlc_roles_data['person_validation_key'],
                                                           'user_id': hlc_roles_data['user_id'],
                                                           'user_profile_id': user_profile_id},
                                                          options['selected_profile_name'],
                                                          options['user_profile_category'],
                                                          options['user_profile_subcategory'],
                                                          hlc_roles_data['person_validation_key'],
                                                          hlc_roles_data['user_validation_key'])
        return {"errCode": 0, "msg": {'component_data': component_json,
                                      'sidebar_data': sidebar_data,
                                      'hlc_roles_data': user_roles_keys}}


class GetBizOrg(Resource):

    def post(self):

        options = request.get_json()
        # hlc_roles_data = json.loads(options.get('hlc_roles_data'))
        hlc_roles_data = get_flask_user_dict()  # New way to get roles_data
        # df = DynamicFilter()
        hlcsession = dbsession



        query = hlcsession.query(BizOrg).filter(BizOrg.hlc_platform_role['biz_org_key'].astext == 'corporate_customer')
        roles_obj = BizOrgHomeScreenQuery(RolesData(role_data=hlc_roles_data['rdd']))
        query = roles_obj.parse_query(query)
        # query = df.filter_result(query, hlc_roles_data)
        query = query.all()
        recs = [orm_to_dict_v2(item) for item in query]
        return {"errCode": 0, "msg": recs}


class GetAllAssessmentRoles(Resource):

    def post(self):
        options = request.get_json()
        # hlc_roles_data = json.loads(options.get('hlc_roles_data'))
        hlc_roles_data = get_flask_user_dict()  # New way to get roles_data
        ah = AssessmentHandler()
        retdata = ah.get_all_assessment_roles(90, options['status'],
                                              options.get('columns', None),
                                              hlc_roles_data, hlc_roles_data['profile_name'])
        return retdata


class GetAssessmentsForCorporate(Resource):

    def post(self):
        options = request.get_json()
        hlc_roles_data = json.loads(options.get('hlc_roles_data'))
        ah = AssessmentHandler()
        retdata = ah.get_assessments_for_corporate(hlc_roles_data, options['assessment_status'])
        return retdata


class GetAssessmentsAttemptedForCorporate(Resource):

    def post(self):
        options = request.get_json()
        hlc_roles_data = json.loads(options.get('hlc_roles_data'))
        ah = AssessmentHandler()
        retdata = ah.get_assessment_attempt_for_corporate(hlc_roles_data, options['assessment_group_id'])
        return retdata


class GetAssessmentsForPersonWithProvider(Resource):

    def post(self):
        options = request.get_json()
        hlc_roles_data = json.loads(options.get('hlc_roles_data'))
        ah = AssessmentHandler()
        retdata = ah.get_allocated_assessments(options['person_id'], hlc_roles_data)
        return retdata


class GetAssessmentsDatesForPersonWithProvider(Resource):

    def post(self):
        options = request.get_json()
        hlc_roles_data = json.loads(options.get('hlc_roles_data'))
        ah = AssessmentHandler()
        retdata = ah.get_allocated_assessment_dates(options['person_id'], options['assessment_id'], hlc_roles_data)
        return retdata


class CreatePerson(Resource):

    def post(self):
        options = request.get_json()
        obj = DataCreator()
        retdata = obj.create_person(options['person_payload'])
        return retdata


class GetAssessmentDates(Resource):

    def post(self):
        options = request.get_json()
        obj = AssessmentHandler()
        retdata = obj.get_assessment_dates(options['assessment_id'])
        return retdata


class GetAttemptedAnswerCountV2(Resource):

    def post(self):
        options = request.get_json()
        # hlc_roles_data = json.loads(options['hlc_roles_data'])
        hlc_roles_data = get_flask_user_dict()  # New way to get roles_data
        obj = AssessmentHandler()
        retdata = obj.get_assessment_attempt_count(options['assessment_group_id'],
                                                   hlc_roles_data, hlc_roles_data['profile_name'],
                                                   options['assessment_id'])
        return retdata


class GetAllGroupRoles(Resource):

    def post(self):
        options = request.get_json()
        hlc_roles_data = json.loads(options['hlc_roles_data'])
        # hlc_roles_data = options['hlc_roles_data']
        obj = GroupHandler()
        retdata = obj.get_all_group_roles(hlc_roles_data, options.get('is_mpg', 0))
        return retdata


class GetAllGroupRolesWithProviders(Resource):

    def post(self):
        options = request.get_json()
        # hlc_roles_data = json.loads(options['hlc_roles_data'])
        hlc_roles_data = get_flask_user_dict()  # New way to get roles_data
        obj = GroupHandler()
        retdata = obj.get_all_group_roles_with_providers(hlc_roles_data)
        return retdata


class GetMPGGroupRoles(Resource):

    def post(self):
        options = request.get_json()
        # hlc_roles_data = json.loads(options['hlc_roles_data'])
        hlc_roles_data = get_flask_user_dict()  # New way to get roles_data
        obj = GroupHandler()
        retdata = obj.get_mpg_group_roles(hlc_roles_data)
        return retdata


class GetPatientGroupsForProvider(Resource):

    def post(self):
        options = request.get_json()
        # hlc_roles_data = json.loads(options['hlc_roles_data'])
        hlc_roles_data = get_flask_user_dict()  # New way to get roles_data
        obj = GroupHandler()
        retdata = obj.patient_group_for_provider(hlc_roles_data)
        return retdata


class AllocateRole(Resource):
    def post(self):
        options = request.get_json()
        obj = UserRoles()
        retdata = obj.allocate_role(int(options['user_id']), int(options['role_id']))
        return retdata


class BreadcrumbService(Resource):
    def post(self):
        options = request.get_json()
        obj = BreadCrumb()
        print("********************BreadCrum=***********************")
        retdata = obj.get_breadcrumb_data(options['tablename'],
                                          options['data_col'],
                                          options['filter_col'],
                                          options['filter_val'])
        return retdata


class SendAssessmentReport(Resource):

    def add_comment(self, session, new_comment, assessment_group_id, person_id):
        assessment_answer_rec = session.query(AssessmentAnswersJson). \
            filter(AssessmentAnswersJson.answer2assessment_group == assessment_group_id,
                   AssessmentAnswersJson.answer2person == person_id).first()
        if assessment_answer_rec.answer_comments:
            comments = dict(assessment_answer_rec.answer_comments)
        else:
            comments = {'comments': []}
        comment_data = comments['comments']
        comment_data.append({'comment': new_comment, 'create_datetime': datetime.now().strftime('%Y-%m-%dT%H:%M:%S')})
        session.query(AssessmentAnswersJson). \
            filter(AssessmentAnswersJson.answer2assessment_group == assessment_group_id,
                   AssessmentAnswersJson.answer2person == person_id).update(
            {'answer_comments': {'comments': comment_data}}
        )
        session.commit()

    def create_report(self, assessment_id, assessment_group_id, person_id, send_mail, new_comment):
        session = dbsession
        report_type = session.query(AssessmentQuestionaire.hlc_role). \
            filter(AssessmentQuestionaire.id == assessment_id).first()[0]

        assessment_obj = AssessmentHandler()
        retdata = assessment_obj.create_refresh_analytics_view(assessment_group_id, report_type)

        if new_comment:
            self.add_comment(session, new_comment, assessment_group_id, person_id)
        if report_type == 'panas':
            obj = CreatePDFData(assessment_id=assessment_id, assessment_group_id=assessment_group_id,
                                person_id=person_id, send_mail=send_mail, new_comment=new_comment)
            return obj.create_individual_report()
        elif report_type == 'panasold':
            obj = CreatePDFDataOld(assessment_id=assessment_id, assessment_group_id=assessment_group_id,
                                   person_id=person_id, send_mail=send_mail, new_comment=new_comment)
            return obj.create_individual_report()
        elif report_type == 'hra':
            obj = CreateData(assessment_id=assessment_id, assessment_group_id=assessment_group_id, person_id=person_id,
                             send_mail=send_mail, new_comment=new_comment)
            return obj.create_hra_report()
        elif report_type == 'hra_workforce':
            obj = CreateDataHraWorkforce(assessment_id=assessment_id, assessment_group_id=assessment_group_id,
                                         person_id=person_id,
                                         send_mail=send_mail, new_comment=new_comment)
            return obj.create_report_workforce_hra()
        elif report_type == 'hraworkforce':
            obj = CreateDataHraWorkforceOffcial(assessment_id=assessment_id, assessment_group_id=assessment_group_id,
                                         person_id=person_id,
                                         send_mail=send_mail, new_comment=new_comment)
            return obj.create_hra_report()
        elif report_type == 'hraglacierwealth':
            obj = CreateDataHraGlacierWealth(assessment_id=assessment_id, assessment_group_id=assessment_group_id,
                                         person_id=person_id,
                                         send_mail=send_mail, new_comment=new_comment)
            return obj.create_hra_report()
        else:
            return {'errCode': 4, 'msg': 'Individual Report not implemented for this type of assessment.'}

    def post(self):
        payload = request.get_json()
        assessment_id = payload['assessment_id']
        assessment_group_id = payload['assessment_group_id']
        person_id = payload['person_id']
        send_mail = payload.get('send_mail', False)
        new_comment = payload.get('comments', '')
        return self.create_report(assessment_id=assessment_id, assessment_group_id=assessment_group_id,
                                  person_id=person_id, send_mail=send_mail, new_comment=new_comment)


class InsertChatFriendsBooking(Resource):
    def post(self):
        options = request.get_json()
        obj = CometChatHelper()
        # retdata = obj.create_chat_friends_booking(options['provider_person_id'], options['booker_user_id'],
                                                #   options['chat_type'], options['start_time'], options['end_time'])
        retdata = obj.create_chat_friends_v2(options['provider_person_id'], options['booker_user_id'],
                                                  options['provider_name'], options['booker_name'],options['chat_type'],options['start_time'],options['end_time'])
        return retdata


class CometChatUserMessage(Resource):
    def post(self):
        options = request.get_json()
        obj = CometChatHelper()
        retdata = obj.get_comet_chat_user_message(options['start_date'], options['end_date'],options['user_id'],options['receiver_id'],options['querystring'])
        return retdata

class GetBookingHistory(Resource):
    def post(self):
        options = request.get_json()
        obj = BookingHandler()
        retdata = obj.get_booking_history(options)
        return retdata


class GetUsersRoles(Resource):
    def post(self):
        options = request.get_json()
        obj = UserRoles()
        retdata = obj.get_user_roles(options['user_id'])
        return retdata


class UpdateUserRoles(Resource):
    def post(self):
        options = request.get_json()
        obj = UserRoles()
        retdata = obj.update_roles(options['user_id'], options['roles'])
        return retdata


# class CreateHRAReport(Resource):
#     def post(self):
#         options = request.get_json()
#         obj = CreateData(options['assessment_id'], options['assessment_group_id'], options['person_id'])

class GetAllEngagmentRoles(Resource):

    def post(self):
        options = request.get_json()
        # hlc_roles_data = json.loads(options.get('hlc_roles_data'))
        hlc_roles_data = get_flask_user_dict()  # New way to get roles_data
        EH = EngagementHelper()
        retdata = EH.get_all_engagement_roles(90, options['status'],
                                              options.get('columns', None),
                                              hlc_roles_data, hlc_roles_data['profile_name'],
                                              options.get('num_records', None))
        return retdata


# class SaveEngagmentJSON(Resource):
#
#     def post(self):
#         options = request.get_json()
#         EH = EngagementHelper()
#         retdata = EH.create_engagement_plan(options['fusion_json'], options['engagement_plan_data'],
#                                             options['provider_id'], options['practitioner_id'])
#         return retdata


class SaveEngagmentJSON(Resource):

    def post(self):
        options = request.get_json()
        EH = EngagementServices()
        retdata = EH.create_engagement(options['fusion_json'], options['engagement_plan_data'],
                                       options['provider_id'], options['practitioner_id'])
        return retdata


class GetEngagement(Resource):

    def post(self):
        options = request.get_json()
        EH = EngagementHelper()
        retdata = EH.get_engagement_json(options['engagement_id'])
        return retdata


# class UpdateEngagement(Resource):
#
#     def post(self):
#         options = request.get_json()
#         EH = EngagementHelper()
#         retdata = EH.update_engagement_json(options['engagement_id'], options['engagement_data'])
#         return retdata


class UpdateEngagement(Resource):

    def post(self):
        options = request.get_json()
        EH = EngagementServices()
        retdata = EH.update_engagement(options['engagement_id'], options['engagement_data'])
        return retdata


class GetEngagementMembers(Resource):

    def post(self):
        options = request.get_json()
        # hlc_roles_data = json.loads(options.get('hlc_roles_data'))

        hlc_roles_data = get_flask_user_dict()  # New way to get roles_data
        EH = EngagementHelper()
        # retdata = EH.get_engagement_members(options['enagagement_id'], hlc_roles_data)
        retdata = EH.get_engagement_members_v2(options['enagagement_id'], hlc_roles_data)
        return retdata


class GetEngagementInstance(Resource):

    def post(self):
        options = request.get_json()
        # hlc_roles_data = json.loads(options.get('hlc_roles_data'))
        hlc_roles_data = get_flask_user_dict()  # New way to get roles_data

        EH = EngagementHelper()
        # retdata = EH.get_engagement_instance(options['engagement_id'], options['person_id'])
        retdata = EH.get_engagement_for_member(options['person_id'], hlc_roles_data)
        return retdata


# class AlllocateEngagement(Resource):
#
#     def post(self):
#         options = request.get_json()
#         EH = EngagementHelper()
#         retdata = EH.allocate_engagement(options['engagement_id'], options['group_id'])
#         return retdata


class AlllocateEngagement(Resource):

    def post(self):
        options = request.get_json()
        EH = EngagementServices()
        retdata = EH.allocate_engagement_to_group(options['engagement_id'], options['group_id'])
        return retdata


class ExtendEngagement(Resource):

    def post(self):
        options = request.get_json()
        EH = EngagementServices()
        retdata = EH.extend_engagement_to_group(options['engagement_id'])
        return retdata


class GetAllVideos(Resource):

    def post(self):
        options = request.get_json()
        VH = VideoHandler()
        retdata = VH.get_all_videos(options.get('video_id', None))
        return retdata


class AddVideo(Resource):

    def post(self):
        options = request.get_json()
        VH = VideoHandler()
        retdata = VH.add_video(options['video_data'])
        return retdata


class UpdateVideo(Resource):

    def post(self):
        options = request.get_json()
        VH = VideoHandler()
        retdata = VH.update_video(options['video_id'], options['vider_data'], options['update_type'])
        return retdata


class GetAllEvents(Resource):

    def post(self):
        options = request.get_json()
        # hlc_roles_data = json.loads(options.get('hlc_roles_data'))
        hlc_roles_data = get_flask_user_dict()  # New way to get roles_data

        EH = EventsHandler()
        retdata = EH.get_all_events(options.get('provider_id', None), options['practitioner_id'], options['status'],
                                    hlc_roles_data, options.get('biz_id', None), options.get('event_type', []),
                                    options.get('event_class_type', ''))
        return retdata


class AddEvent(Resource):

    def post(self):
        options = request.get_json()
        EH = EventsHandler()
        retdata = EH.create_event_data(options['event_payload'])
        return retdata


# TODO Use the new Service
# class AddEvent(Resource):
#
#     def post(self):
#         options = request.get_json()
#         EH = EventsService()
#         retdata = EH.create_event_data(options['event_payload'])
#         return retdata


class PublishEvent(Resource):

    def post(self):
        options = request.get_json()
        EH = EventsHandler()
        retdata = EH.publish_event(options['event_id'], options['events_json'], options['division_id'],
                                   options['practitioner_id'], options['provider_id'], options['start_date'])
        return retdata


class GetEventsSchedule(Resource):

    def post(self):
        options = request.get_json()
        EH = EventsHandler()
        retdata = EH.get_event_schedule(options['practitioner_id'], options['division_id'], options['status'])
        return retdata


class CheckEventSlot(Resource):

    def post(self):
        options = request.get_json()
        EH = EventsHandler()
        retdata = EH.check_event_availability(options['event_id'])
        return retdata


class BookEvent(Resource):

    def post(self):
        options = request.get_json()
        EH = EventsHandler()
        retdata = EH.create_booking_for_person(options['event_id'], options['person_id'], options['company_name'],
                                               options['phone_number'], options.get('engagement_data', None))
        return retdata


# TODO Use the new Service
# class BookEvent(Resource):
#
#     def post(self):
#         options = request.get_json()
#         EH = EventsService()
#         retdata = EH.add_class_booking(options['event_id'], options['person_id'], options['company_name'],
#                                                options['phone_number'], options.get('engagement_data', None))
#         return retdata

class GetEventPersonList(Resource):

    def post(self):
        options = request.get_json()
        EH = EventsHandler()
        retdata = EH.get_event_persons(options['event_booking_ids'], options['event_date'])
        return retdata


class MarkEventAttendance(Resource):

    def post(self):
        payload = request.get_json()
        EH = EventsService()
        retdata = EH.mark_event_attendance(payload['event_booking_id'], payload['attendance_id'])
        return retdata


# class MarkEventAttendance(Resource):
#
#     def handle_event_attendance(self, attendance_id, event_booking_id):
#         attendance_rec = self.hlcsession.query(EventsAttendance).filter(
#             EventsAttendance.id == int(attendance_id)).update({'status': 1})
#         self.hlcsession.flush()
#         event_booking_rec = self.hlcsession.query(EventsBooking). \
#             filter(EventsBooking.id == event_booking_id). \
#             first()
#
#         # Update the status of the engagement instance if found. If all classes are attended mark as engagement activity
#         # completed, else mark as in progress.
#         if event_booking_rec.events_booking_engagement_instance:
#             instance_rec = self.hlcsession.query(EngagementInstance). \
#                 filter(EngagementInstance.id == event_booking_rec.events_booking_engagement_instance).first()
#             if not instance_rec:
#                 self.hlcsession.rollback()
#                 return {"errCode": 2, "msg": "Engagement Record not found."}
#             all_attendance_recs = self.hlcsession.query(EventsAttendance). \
#                 filter(EventsAttendance.this_object2events_booking == event_booking_id,
#                        EventsAttendance.status == 0). \
#                 all()
#             if not all_attendance_recs:
#                 engagement_obj = EngagementHelper()
#                 engagement_response = engagement_obj.complete_activity(instance_rec.instance2engagement,
#                                                                        instance_rec.instance2activity,
#                                                                        instance_rec.instance2person, commit_flag=False)
#                 if engagement_response['errCode'] != 0:
#                     self.hlcsession.rollback()
#                     return engagement_response
#             else:
#                 instance_rec.activity_status = 4
#         try:
#             self.hlcsession.commit()
#             return {'errCode': 0, 'msg': 'Successfully updated status'}
#         except Exception as e:
#             self.hlcsession.rollback()
#             return {'errCode': 1, 'msg': 'Error in updating status', 'err': str(e)}
#
#     def post(self):
#         payload = request.get_json()
#         EH = EventsHandler()
#         self.hlcsession = dbsession
#         retdata = self.handle_event_attendance(payload['attendance_id'], payload.get('event_booking_id', -1))
#         return retdata


# class MarkIndividualAttendance(Resource):
#
#     def post(self):
#         payload = request.get_json()
#         BH = BookingHandler()
#         retdata = BH.mark_individual_attendance(payload['booking_id'])
#         return retdata


class MarkIndividualAttendance(Resource):

    def post(self):
        payload = request.get_json()
        BH = BookingService()
        retdata = BH.mark_booking_attendance(payload['booking_id'])
        return retdata


class GetAssessmentGroupRec(Resource):

    def post(self):
        '''
        :return:
        Get the assessment group rec for given assessment group id. Used for getting assessment for engagement, fetch
        using view created on engagement activity.
        Remove this service, get from get_engagement_keys only.
        '''
        options = request.get_json()
        hlcsession = dbsession
        assessment_group_rec = hlcsession.query(AssessmentGroup). \
            filter(AssessmentGroup.id == options['assessment_group_id']).first()
        assessment_group_data = {'assessment_id': assessment_group_rec.this_object2assessment,
                                 'end_datetime': str(assessment_group_rec.end_datetime)}
        return {"errCode": 0, "msg": [assessment_group_data]}


class CompleteVideo(Resource):

    def post(self):
        options = request.get_json()
        VH = VideoHandler()
        retdata = VH.complete_video(options['engagement_instance_id'])
        return retdata


class GetEventsRoles(Resource):

    def post(self):
        options = request.get_json()
        print options
        EH = EventsHandler()
        retdata = EH.get_events_practitioner(options['practitioner_id'], options.get('status', 2))
        return retdata


class GetInternalProvidersEngagement(Resource):

    def post(self):
        options = request.get_json()
        hlc_roles_data = json.loads(options.get('hlc_roles_data'))
        obj = BookingHandler()
        retdata = obj.get_internal_provider_bookings(hlc_roles_data)
        return retdata


# class GetDatetimes(Resource):
#
#     def post(self):
#         payload = request.get_json()
#         return parse_payload(payload)


class GetEngagementKeys(Resource):

    def __init__(self):
        self.engagement_map = {'group': self.get_event_data,
                               'individual': self.get_individual_schedule_data,
                               'assessment': self.get_assessment_data,
                               'multi_prac': self.get_multi_prac_schedule}

    def get_event_data(self, payload):
        events_list = payload['events_list']
        # Events list can one event id or multiple events, convert it into list before query.
        if not isinstance(events_list, list):
            events_list = [int(events_list)]
        hlcsession = dbsession
        event_recs = hlcsession.query(EventsBookingViewV3.event_id,
                                      label('num_persons_enrolled', func.count(EventsBookingViewV3.events_booking_id)),
                                      EventsBookingViewV3.num_participants). \
            filter(EventsBookingViewV3.event_id.in_(events_list)). \
            group_by(EventsBookingViewV3.event_id,
                     EventsBookingViewV3.num_participants).all()
        event_ids = filter(lambda x: int(x.num_persons_enrolled) < int(x.num_participants), event_recs)
        event_ids = [item.event_id for item in event_ids]
        event_recs = hlcsession.query(GetEventsViewV2). \
            filter(GetEventsViewV2.event_id.in_(event_ids)). \
            distinct(GetEventsViewV2.event_id). \
            all()

        event_recs = [{'events2div_org': item.event_division_id,
                       'events2practitioner': item.event_practitioner_id,
                       'start_date': str(item.event_start_date),
                       'end_date': str(item.event_end_date),
                       'event_name': item.event_name,
                       'price': item.price,
                       'id': item.event_id} for item in event_recs]
        # return 0, event_recs, None
        return {"errCode": 0, "msg": event_recs}

    def get_individual_schedule_data(self, payload):
        practitioner_id = payload['practitioner_id']
        division_id = payload['division_id']
        # schedule_obj = BookingHandler()
        # schedule_recs = schedule_obj.get_booking_data(practitioner_id, division_id, datetime.now(), 1, None)
        schedule_obj = ScheduleDataServices()
        schedule_recs = schedule_obj.get_booking_data(practitioner_id, division_id, datetime.now(), 1, None)
        return schedule_recs

    def get_assessment_data(self, payload):
        hlcsession = dbsession
        assessment_group_rec = hlcsession.query(AssessmentGroup). \
            filter(AssessmentGroup.id == payload['assessment_group_id']).first()
        assessment_group_data = {'assessment_id': assessment_group_rec.this_object2assessment,
                                 'end_datetime': str(assessment_group_rec.end_datetime)}
        # return 0, assessment_group_data, None
        return {"errCode": 0, "msg": assessment_group_data}

    def get_multi_prac_schedule(self, payload):
        practitioner_group_id = payload['practitioner_group_id']
        start_date = payload.get('start_date', None)
        if not start_date:
            # start_date = datetime.now().date() + timedelta(days=1)
            start_date = datetime.now().date()
        else:
            start_date = parse(start_date)
        obj = BookingHandler()
        retdata = obj.get_booking_data_multipractitioner_group(practitioner_group_id, start_date, 1, None)
        return retdata

    def post(self):
        options = request.get_json()
        payload = options['payload']
        engagement_type = options['engagement_type']
        # errCode, engagement_data, metadata = self.engagement_map[engagement_type](payload)
        retdata = self.engagement_map[engagement_type](payload)
        return retdata
        # return {"errCode": errCode, "msg": engagement_data, 'next_date': metadata}


class GetCorporateEventParticipants(Resource):

    def post(self):
        '''
        :return:
        Get the list of all corporate employees enrolled for a particular event.
        '''
        options = request.get_json()
        bizorg_id = options['bizorg_id']
        events_id = options['event_id']
        EH = EventsHandler()
        retdata = EH.get_corporate_participants_for_event(bizorg_id, events_id)
        return retdata


class PublishCorporateEvent(Resource):

    def post(self):
        options = request.get_json()
        EH = EventsHandler()
        retdata = EH.publish_corporate_event(options['event_id'], options['providers_list'],
                                             options.get('assessment_list'), options.get('bizorg_id', None))
        return retdata


class HandleEventInvitation(Resource):

    def events_invite_handler(self, data, event_id, email_type, invite_type, session):
        data['event_id'] = event_id
        jwt_token = json.loads(base64.b64decode(data['token']))['jwt_token']

        events_invite_rec = EventsInivite(events_invite2events=event_id,
                                          events_invite2person=data.get('person_id'),
                                          invite_status=0,
                                          num_times_invited=1,
                                          invite_send_date=datetime.now(),
                                          invite_type=invite_type,
                                          email_id=data.get('email'),
                                          token=jwt_token)
        try:
            session.add(events_invite_rec)
            # session.flush()
            session.commit()
            EmailHandler().send_mail.delay(email_type, **data)
            return {'errCode': 0, 'msg': 'Email sent to '}
        except Exception as e:
            session.rollback()
            return {'errCode': 1, 'msg': str(e)}

    def post(self):
        payload = request.get_json()
        print payload
        event_id = int(payload['event_id'])
        bizorg_id = int(payload['bizorg_id'])
        session = dbsession
        # updating event status
        event_rec = session.query(Events).filter(Events.id == event_id).one()
        event_data = orm_to_dict_v2(event_rec)
        event_rec.status = 4

        # checking already existing users in other emails list and handling them.
        employee_emails = payload.get('employee_emails', [])
        other_emails = payload.get('other_emails', [])
        check_user_recs = session.query(User).filter(User.user_name.in_([rec['email'] for rec in other_emails])).all()
        user_recs = [{'email': rec.user_name, 'person_id': rec.user2person}
                     for rec in check_user_recs]
        other_emails = [rec for rec in other_emails if rec['email'] not in [rec['email'] for rec in user_recs]]
        for email_rec in (employee_emails + user_recs):
            email_rec['jwt_token'] = encode_text(email_rec['email'])
            email_rec['token'] = base64.b64encode(json.dumps({'person_id': email_rec['person_id'], 'event_id': event_id,
                                                              'jwt_token': email_rec['jwt_token'],
                                                              'email': email_rec['email']}))
            email_rec.update({'event_name': event_data['event_name'],
                              'event_date': event_rec.start_date.strftime('%A, %B %d,%Y'),
                              'event_description': event_data['event_description'],
                              'email': email_rec['email']})
            self.events_invite_handler(email_rec, event_id, 'current_member_event_register',
                                       'corporate_member', session)
        for email_rec in other_emails:
            email_rec['jwt_token'] = encode_text(email_rec['email'])
            email_rec['token'] = base64.b64encode(json.dumps({'event_id': event_id,
                                                              'jwt_token': email_rec['jwt_token'],
                                                              'bizorg_id': bizorg_id,
                                                              'email': email_rec['email']}))
            email_rec.update({'event_name': event_data['event_name'],
                              'event_date': event_rec.start_date.strftime('%A, %B %d,%Y'),
                              'event_description': event_data['event_description'],
                              'email': email_rec['email']})
            self.events_invite_handler(email_rec, event_id, 'new_user_event_register',
                                       'mail_list', session)
            try:
                session.commit()
            except Exception as e:
                session.rollback()
                return {'errCode': 2, 'msg': 'Error in updating event status.'}
        return {'errCode': 0, 'msg': 'Emails Sent.'}


class UpdateEventInviteStatus(Resource):

    def post(self):
        payload = request.get_json()
        token = payload['token']
        status = payload['status']
        session = dbsession
        event_handler_obj = EventsHandler()
        event_rec = session.query(EventsInivite).filter(EventsInivite.token == token).first()
        if event_rec:
            event_invite_data = orm_to_dict_v2(event_rec)
            if event_invite_data['invite_status'] == 2:
                # This means already registered and user clicks on register for event link.
                return {'errCode': 1, 'msg': 'Already registered for event'}
            else:
                event_rec.invite_status = status
                event_booking_data = event_handler_obj.create_booking_for_corporate_event(
                    event_rec.events_invite2events,
                    event_rec.events_invite2person,
                    commit_flag=False)
                if event_booking_data['errCode'] != 0:
                    return event_booking_data
                try:
                    # pass
                    # session.flush()
                    session.commit()
                    return {'errCode': 0, 'msg': 'Event status updated', 'status': status}
                except Exception as e:
                    session.rollback()
                    return {'errCode': 2, 'msg': 'Error in updating event status.'}
        else:
            return {'errCode': 3, 'msg': 'Event not found.'}


class UpdateEventInvitePerson(Resource):

    def post(self):
        payload = request.get_json()
        token = payload['token']
        person_id = payload['person_id']
        session = dbsession
        _ = session.query(EventsInivite).filter(EventsInivite.token == token). \
            update({'events_invite2person': person_id})
        try:
            session.commit()
            return {'errCode': 0, 'msg': 'Updated person id in event invite'}
        except Exception as e:
            session.rollback()
            return {'errCode': 1, 'msg': 'Error in updating person id', 'err': str(e)}


class GetCorporateEventParticipantsData(Resource):

    def post(self):
        options = request.get_json()
        EH = EventsHandler()
        retdata = EH.get_corporate_event_participant_data(options['event_id'])
        return retdata


class UpdateFeedback(Resource):

    def post(self):
        options = request.get_json()
        EH = EventsHandler()
        feedback_type = options['feedback_type']
        if feedback_type == 'event':
            retdata = EH.update_event_feedback(options['feedback_id'], options['feedback_payload'])
        else:
            return {"errCode": 4, "msg": "Bad feedback type."}
        return retdata


class AddNonMembersToEvent(Resource):

    def post(self):
        options = request.get_json()
        EH = EventsHandler()
        print options
        retdata = EH.add_non_members_to_event_handler(options['event_id'], options['payload'], options['case'],
                                                      options.get('bizorg_id', -1), options.get('token', ''))
        return retdata


class GetAllAssessmentEvents(Resource):

    def filter_assessments(self, event_id, retdata):
        session = dbsession
        event_assessments = session.query(EventsAssessments.events_assessments2assessment). \
            filter(EventsAssessments.events_assessment2events == event_id,
                   EventsAssessments.status == 1).all()
        event_assessment_ids = [rec[0] for rec in event_assessments]
        for rec in retdata:
            if rec['assessment_id'] in event_assessment_ids:
                rec['status'] = 1
            else:
                rec['status'] = 0
        return retdata

    def post(self):
        options = request.get_json()
        event_id = options.get('event_id')
        # hlc_roles_data = json.loads(options.get('hlc_roles_data'), json.dumps({}))
        hlc_roles_data = None
        ah = AssessmentHandler()
        retdata = ah.get_all_assessments_events(options['status'],
                                                options.get('columns', None),
                                                hlc_roles_data)
        if event_id:
            retdata = self.filter_assessments(event_id, retdata['msg'])
            ret_data = {'errCode': 0, 'msg': retdata}
        return ret_data


class GetEventProvidersAssessments(Resource):

    def post(self):
        options = request.get_json()
        EH = EventsHandler()
        retdata = EH.get_events_providers_assessments(options['event_id'])
        return retdata


class GetEventRec(Resource):

    def post(self):
        options = request.get_json()
        EH = EventsHandler()
        retdata = EH.get_event_data(options['event_id'])
        return retdata


class SendFeedbackEmail(Resource):

    def post(self):
        options = request.get_json()
        EH = EventsHandler()
        retdata = EH.send_feedback_email(**options)
        return retdata


class GetAssessmentMetaData(Resource):

    def post(self):
        options = request.get_json()
        AH = AssessmentHandler()
        retdata = AH.get_assessment_metatda(options['assessment_id'])
        return retdata


class UpdateCorporateEvent(Resource):

    def post(self):
        payload = request.get_json()
        EH = EventsHandler()
        retjson = EH.update_event(payload['event_id'], payload['event_payload'])
        return retjson


class UpdateDivisionData(Resource):

    def post(self):
        payload = request.get_json()
        division_data = payload['division_data']
        retjson = {"errCode": 0, "msg": "Successfully updated division."}
        hlcsession = dbsession
        hlcsession.query(DivOrg).filter(DivOrg.id == payload['division_id']).update({'name': division_data['name']})
        try:
            hlcsession.commit()
        except Exception as e:
            print e
            hlcsession.rollback()
            retjson = {"errCode": 1, "msg": str(e)}
        return retjson


class GetProfileDetails(Resource):

    def post(self):
        payload = request.get_json()
        profile_handler = Profile()
        # hlc_roles_data = json.loads(payload.get('hlc_roles_data'))['rdd']
        role_data = get_flask_user_dict()  # New way to get roles_data
        hlc_roles_data = role_data['rdd']

        ret_data = profile_handler.get_profile_details(payload, hlc_roles_data)
        ret_data = {"errCode": 0, "msg": ret_data}
        return ret_data


class UpdateUserProfile(Resource):

    def post(self):
        payload = request.get_json()
        profile_handler = Profile()
        ret_data = profile_handler.update_user_profile(payload)
        return ret_data


class DataTablePreview(Resource):

    def post(self):
        payload = request.get_json()
        case = payload['case']
        th = TablePreview(case)
        retdata = th.get_data(payload)
        return retdata


class GetOtherClassifications(Resource):

    def post(self):
        hlcsession = dbsession
        recs = dbsession.query(ClassificationOther).all()
        recs = [orm_to_dict_v2(item) for item in recs]
        return {"errCode": 0, "msg": recs}


class AllInternalProviderSchedue(Resource):

    def post(self):
        payload = request.get_json()
        SH = BookingHandler()
        retdata = SH.get_all_internal_provider_sched()
        return {'errCode': 0, 'msg': retdata}


class InternalPractitionerLocations(Resource):

    def post(self):
        obj = MakeTreeV2()
        retdata = obj.get_all_practitioner_locations()
        return {'errCode': 0, 'msg': retdata}


class AddOtherClassification(Resource):

    def post(self):
        options = request.get_json()
        payload = options['other_classification']
        person_id = options['person_id']
        obj = OtherClassification()
        retdata = obj.add_new_classification_value(payload, person_id)
        return retdata


# class DeleteEmployeeNonCore(Resource):
#     def post(self):
#         # return {"errCode": 1, "msg": "Method Not Found."}
#         eh = EH.HandleEmployeeDivs()
#         options = request.get_json()
#         retjson = eh.delete_employee_from_corporate(int(options["person_id"]), options["bizorg_id"],
#                                                     options["end_date"], int(options["employee_id"]))
#         # retjson = eh.remove_emp_from_div(options["div_id"],options["person_id"],options["biz_id"])
#         # eh.hlcsession.close()
#         return retjson


class GetDeletedEmployees(Resource):

    def post(self):
        options = request.get_json()
        hlcsession = dbsession
        case = options['case']
        if case == 'corporate':
            result = hlcsession.query(HlcEmployeeView).distinct(HlcEmployeeView.employee_id). \
                filter(HlcEmployeeView.bizorg_id == options['bizorg_id'],
                       HlcEmployeeView.employee_active_status == False)
        else:
            result = []
        result = result.all()
        result = [orm_to_dict_v2(item) for item in result]
        return {"errCode": 0, "msg": result}


class UseOtherClassification(Resource):

    def post(self):
        options = request.get_json()
        payload = options['classification_payload']
        obj = OtherClassification()
        retdata = obj.use_classification_value(payload)
        return retdata


class CreateInquiry(Resource):

    def post(self):
        options = request.get_json()
        obj = InquiryHandler()
        retdata = obj.create_inquiry(options['inquiry_payload'])
        return retdata


class GetAllInquiries(Resource):

    def post(self):
        options = request.get_json()
        obj = InquiryHandler()
        retdata = obj.get_all_inquiries(options['inquiry_type'])
        return retdata


class UpdateInquiry(Resource):

    def post(self):
        options = request.get_json()
        obj = InquiryHandler()
        retdata = obj.update_inquiry(options['inquiry_id'], options['payload'])
        return retdata


class GetWidgetsForRoles(Resource):

    def post(self):
        options = request.get_json()
        hlc_roles_data = json.loads(options.get('hlc_roles_data'))
        obj = WidgetHandler(hlc_roles_data)
        retdata = obj.get_roles_widgets(options['roles_list'])
        return retdata


class GetHomepageWidgets(Resource):

    def post(self):
        options = request.get_json()
        # hlc_roles_data = json.loads(options.get('hlc_roles_data'))
        hlc_roles_data = get_flask_user_dict()  # New way to get roles_data
        obj = WidgetHandler(hlc_roles_data)
        retdata = obj.get_homepage_widgets()
        return retdata


class SaveUserWidgets(Resource):

    def post(self):
        options = request.get_json()
        hlc_roles_data = json.loads(options.get('hlc_roles_data'))
        obj = WidgetHandler(hlc_roles_data)
        retdata = obj.save_user_widgets(options['widget_data'])
        return retdata


class PromoteEmployeeToUser(Resource):

    def post(self):
        options = request.get_json()
        obj = EH.HandleEmployeeDivs()
        retMsg = obj.convert_employee_to_user(options['person_id'], options['bizorg_id'], options['user_details'])
        return retMsg


class GetClassBookings(Resource):

    def post(self):
        payload = request.get_json()
        EH = EventsHandler()
        hlc_roles_data = json.loads(payload['hlc_roles_data'])
        retjson = EH.get_class_bookings(hlc_roles_data)
        return retjson


class ViewUpdateEmployeeNonCore(Resource):

    def post(self):
        # return {"errCode":1, "msg": "Method Not Found."}
        options = request.get_json()
        obj = EH.HandleEmployeeDivs()
        retMsg = obj.view_update_employee(options['employee_payload'])
        return retMsg


class ViewPractitionerDetails(Resource):

    def post(self):
        options = request.get_json()
        p = MH.HandleMultiSpecialityDivisions()
        retMsg = p.get_practitioner_details(options['multispec_id'], options['person_id'])
        return retMsg


class GetProviderData(Resource):

    def post(self):
        options = request.get_json()
        p = AddData()
        retMsg = p.get_provider_data(options['person_id'], options['bizorg_id'])
        return retMsg


class GetPersonDetails(Resource):

    def post(self):
        payload = request.get_json()
        person_obj = PersonData(payload['person_id'])
        return {'errCode': 0, 'msg': person_obj.get_person_details()}


###############################################################################################33333333
###############################################################################################33333333
# Employee core Services
###############################################################################################33333333
###############################################################################################33333333
###############################################################################################33333333
###############################################################################################33333333

from HLCAPP.core_services.employee_services import EmployeeService


class AddEmployee(Resource):

    def post(self):
        options = request.get_json()
        p = EmployeeService()
        retMsg = p.create_employee(options)
        return retMsg


class AddEmployeeFromOutside(Resource):

    def post(self):
        options = request.get_json()
        p = EmployeeService()
        retMsg = p.add_employee_from_outside(options)
        return retMsg


class AddPersonToDiv(Resource):
    def post(self):
        options = request.get_json()
        eh = EmployeeService()
        retjson = eh.add_employee_to_div(int(options["div_id"]), int(options["person_id"]),
                                         int(options["biz_id"]), options["start_date"],
                                         options["existing_divisions"],
                                         int(options["employee_id"]))
        return retjson


#
#
class RemovePersonFromDiv(Resource):
    def post(self):
        options = request.get_json()
        eh = EmployeeService()
        retjson = eh.remove_employee_from_div(int(options["div_id"]), int(options["person_id"]),
                                              int(options["biz_id"]), options["end_date"], int(options["employee_id"]))
        return retjson


#
class DeleteEmployee(Resource):
    def post(self):
        options = request.get_json()
        eh = EmployeeService()
        retjson = eh.delete_employee_from_corporate(int(options["person_id"]), options["bizorg_id"],
                                                    options["end_date"], int(options["employee_id"]))
        return retjson


#
#
# class ViewUpdateEmployee(Resource):
#
#     def post(self):
#         options = request.get_json()
#         obj = EmployeeService()
#         retMsg = obj.view_update_employee(options['employee_payload'])
#         return retMsg


class GetAllEmailContent(Resource):

    def post(self):
        payload = request.get_json()
        email_obj = EmailContentServices()
        return email_obj.get_all_emails()


class GetAllEmailContentSingle(Resource):

    def post(self):
        payload = request.get_json()
        email_obj = EmailContentServices()
        return email_obj.get_single_email(payload['subject'])


class AddEmailContent(Resource):

    def post(self):
        payload = request.get_json()
        email_obj = EmailContentServices()
        return email_obj.create_email_rec(payload)


class UpdateEmailContent(Resource):

    def post(self):
        payload = request.get_json()
        email_obj = EmailContentServices()
        return email_obj.update_email_rec(payload)


class AddEmailLog(Resource):

    def post(self):
        options = request.get_json()
        obj = EmailLogService()
        retdata = obj.add_email_log(options)
        return retdata


class MPGTree(Resource):

    def post(self):
        payload = request.get_json()
        tree_obj = MakeTree()
        return {'errCode': 0, 'msg': tree_obj.make_mpg_tree(payload['id'], payload['menu_items'])}


class ProviderViewDataAPI(Resource):

    def post(self):
        options = request.get_json()
        obj = ProviderViewQueries()
        retdata = obj.get_provider_view_data(options)
        return retdata

from HLCAPP.core_services.assessment_offline import AssessmentOfflineService

class AssessmentDataOfflineMPG(Resource):

    def post(self):
        options = request.get_json()
        hlc_roles_data = json.loads(options['hlc_roles_data'])
        obj = AssessmentOfflineService()
        retdata = obj.get_offline_assessments_for_mpg(hlc_roles_data)
        return retdata


class UploadOfflineAssessmentDataForMPG(Resource):

    def post(self):
        options = request.get_json()
        hlc_roles_data = json.loads(options['hlc_roles_data'])
        obj = AssessmentOfflineService()
        # retdata = obj.save_and_process_assessment_data_json(hlc_roles_data, options['data_json'])
        retdata = obj.save_and_process_assessment_data_json(hlc_roles_data, options.get('data_json', []))
        return retdata


class ProcessDataJson(Resource):

    def post(self):
        options = request.get_json()
        hlc_roles_data = json.loads(options['hlc_roles_data'])
        obj = AssessmentOfflineService()
        # retdata = obj.save_and_process_assessment_data_json(hlc_roles_data, options['data_json'])
        retdata = obj.process_assessment_data_json(hlc_roles_data, options['data_json_id'])
        return retdata


class GetAllOfflineDataJson(Resource):

    def post(self):
        options = request.get_json()
        hlc_roles_data = json.loads(options['hlc_roles_data'])
        obj = AssessmentOfflineService()
        retdata = obj.get_all_offline_data_json_recs()
        return retdata


class AllowAttemptOnlineForMPG(Resource):

    def post(self):
        options = request.get_json()
        hlc_roles_data = json.loads(options['hlc_roles_data'])
        obj = AssessmentOfflineService()
        retdata = obj.allow_attempt_online_for_mpg(options['data_json_id'])
        return retdata


class CreateCorporateCustomerObj(Resource):

    def post(self):
        options = request.get_json()
        hlc_roles_data = json.loads(options['hlc_roles_data'])
        obj = CorporateCustomerServices()
        retdata = obj.create_corporate_customer(options)
        return retdata


class AddCorporateCustomerDivisionObj(Resource):

    def post(self):
        options = request.get_json()
        hlc_roles_data = json.loads(options['hlc_roles_data'])
        obj = CorporateCustomerServices()
        retdata = obj.add_division_to_corporate(options)
        return retdata
#============Corporate Employee Audit data=====================
class CorporateCustomerEmployeeAuditData(Resource):
    def post(self):
        options = request.get_json()
        emp_audit = CorporateEmployeeDataService(options['person_id'])
        return emp_audit.get_division_history()

class CreateProviderShareLink(Resource):
    def post(self):
        options = request.get_json()
        pds = ProviderDataServices()
        return pds.get_provider_sharable_link(options['provider_id'],options['person_id'],options['division_id'])

class ProviderSharableLink(Resource):
    def post(self):
        options = request.get_json()
        pds = ProviderDataServices()
        return pds.get_all_division_with_address(options['encoded_data'])

class ProviderDivisions(Resource):
    def post(self):
        options = request.get_json()
        pds = ProviderDataServices()
        return pds.get_provider_divisions(options)


class UploadCorporateLogo(Resource):
    def post(self):
        options = request.get_json()
        corp = CorporateQueries()
        # return corp.get_corporate_logo(options['corporate_id'])
        return corp.upload_corporate_logo(options)

class GetCorporateLogo(Resource):
    def post(self):
        options = request.get_json()
        corp = CorporateQueries()
        return corp.get_corporate_logo(options['corporate_id'])

class BookingTransactionData(Resource):
    def post(self):
        options = request.get_json()
        bth = BookingTransactionHistory()
        return bth.get_transaction_history(options)

#==========Medicine discipline
class MedicineDiscipline(Resource):
    def post(self):
        options = request.get_json()
        mds = ConsultationServices()
        return mds.get_all_medicines(options['discipline_id'])



class AssessmentDisciplineMember(Resource):
    def post(self):
        options = request.get_json()
        mds = ConsultationServices()
        return mds.get_all_member_assessments(options)
        # return mds.get_all_member_assessments(options['discipline_id'])

class AssessmentDisciplineProvider(Resource):
    def post(self):
        options = request.get_json()
        mds = ConsultationServices()
        # return mds.get_all_provider_assessments(options['discipline_id'])
        return mds.get_all_provider_assessments(options) # discipline_id,provider_id,person_id

class GetInvestigationByType(Resource):
    def post(self):
        options = request.get_json()
        mds = ConsultationServices()
        return mds.get_investigation_type_data(options)


class GetMemberDetailsConsultation(Resource):
    def post(self):
        options = request.get_json()
        mds = ConsultationServices()
        return mds.get_member_details_consultation(options['booking_transaction_id'])


class GetProviderDetailsConsultation(Resource):
    def post(self):
        options = request.get_json()
        mds = ConsultationServices()
        return mds.get_provider_details_consultation(options['booking_transaction_id'])


class MemberFeedback(Resource):
    def post(self):
        options = request.get_json()
        mds = BookingService()
        return mds.add_feedback_for_booking(options)

class GetMemberFeedback(Resource):
    def post(self):
        options = request.get_json()
        mds = BookingService()
        return mds.get_member_booking_feedback(options['booking_transaction_id'])


class CreatePrescription(Resource):
    def post(self):
        options = request.get_json()
        crtpres = PrescriptionService()
        return crtpres.create_prescription(options)

class UpdatePrescription(Resource):
    def post(self):
        options = request.get_json()
        crtpres = PrescriptionService()
        return crtpres.update_prescription(options)

class CompletePrescription(Resource):
    def post(self):
        options = request.get_json()
        crtpres = PrescriptionService()
        # _payload = {
        #     "status": "Complete",
        #     "prescription_id":options['prescription_id']
        # }
        # return crtpres.update_prescription(_payload)
        return crtpres.complete_prescription(options)


class AddPrescriptionMedicine(Resource):
    def post(self):
        options = request.get_json()
        crtpres = PrescriptionService()
        return crtpres.add_prescription_medicine(options['prescription_id'], options['medicine_list'])

class GetPrescriptionMedicine(Resource):
    def post(self):
        options = request.get_json()
        crtpres = PrescriptionService()
        return crtpres.get_prescription_medicine(options['prescription_id'])

class AddPrescriptionInvestigation(Resource):
    def post(self):
        options = request.get_json()
        crtpres = PrescriptionService()
        return crtpres.add_prescription_investigation(options['prescription_id'], options['investigation_list'])

class AddPrescriptionProcedure(Resource):
    def post(self):
        options = request.get_json()
        crtpres = PrescriptionService()
        return crtpres.add_prescription_procedure(options['prescription_id'], options['procedure_list'])

class GetPrescriptionInvestigation(Resource):
    def post(self):
        options = request.get_json()
        crtpres = PrescriptionService()
        return crtpres.get_prescription_investigation(options['prescription_id'], "investigation")

class GetPrescriptionProcedure(Resource):
    def post(self):
        options = request.get_json()
        crtpres = PrescriptionService()
        return crtpres.get_prescription_investigation(options['prescription_id'], "procedure")

class GetPrescriptionNotes(Resource):
    def post(self):
        options = request.get_json()
        crtpres = PrescriptionService()
        return crtpres.get_prescription_notes(options['prescription_id'], options['is_public'])

class GetPrescriptionData(Resource):
    def post(self):
        options = request.get_json()
        crtpres = PrescriptionDataService()
        return crtpres.get_prescription_data(options['prescription_id'], options['data_keys'])

class GetPrescriptionDetailDoc(Resource):
    def post(self):
        options = request.get_json()
        crtpres = PrescriptionService()
        return crtpres.get_document_from_prescription_detail(options['prescription_detail_id'])

class AddPrescriptionNotes(Resource):
    def post(self):
        options = request.get_json()
        crtpres = PrescriptionService()
        return crtpres.add_prescription_notes(options['prescription_id'], options)

class AddReferallToInvestigation(Resource):
    def post(self):
        options = request.get_json()
        crtpres = PrescriptionService()
        return crtpres.add_referall_to_investigation(options['prescription_id'], options['pres_detail_id'], options)

class AddPrescriptionAssessmentMember(Resource):
    def post(self):
        options = request.get_json()
        crtpres = PrescriptionService()
        return crtpres.add_prescription_assessment_member(options['assessment_id'], options['assessment_data'], options['booking_trans_id'])

class AddPrescriptionAssessmentProvider(Resource):
    def post(self):
        options = request.get_json()
        crtpres = PrescriptionService()
        return crtpres.add_prescription_assessment_provider(options['assessment_id'], options['assessment_data'], options['booking_trans_id'])

class AddPrescriptionReferal(Resource):
    def post(self):
        options = request.get_json()
        crtpres = PrescriptionService()
        return crtpres.add_referall_to_prescription(options['prescription_id'], options)

class GetPrescriptionAssessmentMember(Resource):
    def post(self):
        options = request.get_json()
        crtpres = PrescriptionService()
        return crtpres.get_assessment_from_prescription_id_for_member(options['prescription_id'])

class GetPrescriptionAssessmentProvider(Resource):
    def post(self):
        options = request.get_json()
        crtpres = PrescriptionService()
        return crtpres.get_assessment_from_prescription_id_for_provider(options['prescription_id'])

class UploadMemberDocuments(Resource):
    def post(self):
        options = request.get_json()
        mds = BookingService()
        return mds.upload_booking_member_documents(options)

class GetMemberDocuments(Resource):
    def post(self):
        options = request.get_json()
        mds = BookingService()
        return mds.get_member_booking_documents(options)

class CreateDisciplineAssessment(Resource):
    def post(self):
        payload = request.get_json()
        # hlc_roles_data = json.loads(payload['hlc_roles_data'])
        # rdd_data = hlc_roles_data['rdd']
        role_data = get_flask_user_dict()  # New way to get roles_data
        rdd_data = role_data['rdd']
        mds = DisciplineAssessmentService()
        return mds.create_discipline_asseement(payload,rdd_data)


class GetAllProviderAssessments(Resource):
    def post(self):
        payload = request.get_json()
        # hlc_roles_data = json.loads(payload['hlc_roles_data'])
        # rdd_data = hlc_roles_data['rdd']
        role_data = get_flask_user_dict()
        rdd_data = role_data['rdd']
        mds = DisciplineAssessmentService()
        return mds.get_provider_all_assessments(rdd_data)

class GetProviderAssessmentData(Resource):
    def post(self):
        payload = request.get_json()
        mds = DisciplineAssessmentService()
        return mds.get_provider_assessments_data(payload)

# class DeactivateDisciplineAssessment(Resource):
#     def post(self):
#         payload = request.get_json()
#         hlc_roles_data = json.loads(payload['hlc_roles_data'])
#         rdd_data = hlc_roles_data['rdd']
#         mds = DisciplineAssessmentService()
#         return mds.deactivate_discipline_assessment(payload, rdd_data)

class DeactivateDisciplineAssessment(Resource):
    def post(self):
        payload = request.get_json()
        # hlc_roles_data = json.loads(payload['hlc_roles_data'])
        # rdd_data = hlc_roles_data['rdd']
        role_data = get_flask_user_dict()
        rdd_data = role_data['rdd']
        mds = DisciplineAssessmentService()
        return mds.deactivate_discipline_assessment(payload, rdd_data)

class GetAllDiscplineProvider(Resource):
    def post(self):
        payload = request.get_json()
        # hlc_roles_data = json.loads(payload['hlc_roles_data'])
        # rdd_data = hlc_roles_data['rdd']
        role_data = get_flask_user_dict()
        rdd_data = role_data['rdd']
        mds = DisciplineAssessmentService()
        return mds.get_all_provider_disciplines(rdd_data)

#=============Medicine==============
class GetAllMedicines(Resource):
    def post(self):
        # payload = request.get_json()
        medicine = MedicineService()
        return medicine.get_all_medicines()

class CreateMedicine(Resource):
    def post(self):
        payload = request.get_json()
        medicine = MedicineService()
        return medicine.create_medicine(payload)

class RemoveMedicine(Resource):
    def post(self):
        payload = request.get_json()
        medicine = MedicineService()
        return medicine.remove_medicine(payload['medicine_id'])

class AddMedicineToDiscipline(Resource):
    def post(self):
        payload = request.get_json()
        medicine = MedicineService()
        return medicine.save_medicine_to_discipline(payload)



#=================Discipline===============


class CreateDiscipline(Resource):
    def post(self):
        payload = request.get_json()
        discipline_obj = DisciplineService()
        return discipline_obj.create_discipline(payload)


class UpdateDiscipline(Resource):
    def post(self):
        payload = request.get_json()
        discipline_obj = DisciplineService()
        return discipline_obj.update_discipline(payload['data'],payload['discipline_id'])



#=============Investigation/Procedure==================
class CreateProcedure(Resource):
    def post(self):
        payload = request.get_json()
        investigation_obj = InvestigationProcedureService()
        return investigation_obj.create_procedure(payload)

class GetAllProcedure(Resource):
    def post(self):
        payload = request.get_json()
        investigation_procedure_obj = InvestigationProcedureService()
        return investigation_procedure_obj.get_alll_procedure()

class GetProcedureData(Resource):
    def post(self):
        payload = request.get_json()
        investigation_procedure_obj = InvestigationProcedureService()
        return investigation_procedure_obj.get_procedure_data(payload['procedure_id'])

class RemoveProcedure(Resource):
    def post(self):
        payload = request.get_json()
        investigation_procedure_obj = InvestigationProcedureService()
        return investigation_procedure_obj.remove_procedure(payload['procedure_id'])

class AddProcedureToDiscpline(Resource):
    def post(self):
        payload = request.get_json()
        investigation_procedure_obj = InvestigationProcedureService()
        return investigation_procedure_obj.save_procedure_to_discipline(payload)

class GetAllDisciplineProcedure(Resource):
    def post(self):
        payload = request.get_json()
        investigation_procedure_obj = InvestigationProcedureService()
        return investigation_procedure_obj.get_all_discipline_procedure(payload['discipline_id'])

#=============Investigation==================
class CreateInvetigation(Resource):
    def post(self):
        payload = request.get_json()
        investigation_obj = InvetigationeService()
        return investigation_obj.create_investigation(payload)

class GetAllInvestigation(Resource):
    def post(self):
        payload = request.get_json()
        investigation_obj = InvetigationeService()
        return investigation_obj.get_alll_investigation()

class GetAllInvestigationTree(Resource):
    def post(self):
        payload = request.get_json()
        investigation_obj = InvetigationeService()
        return investigation_obj.get_investigation_tree(payload)


class GetInvestigationData(Resource):
    def post(self):
        payload = request.get_json()
        investigation_obj = InvetigationeService()
        return investigation_obj.get_investigation_data(payload['investigation_id'])

class UpdateInvestigation(Resource):
    def post(self):
        payload = request.get_json()
        investigation_obj = InvetigationeService()
        return investigation_obj.update_investigation(payload['data'],payload['investigation_id'])

class AddInvestigationToDiscpline(Resource):
    def post(self):
        payload = request.get_json()
        investigation_obj = InvetigationeService()
        return investigation_obj.save_investigation_to_discipline(payload)

class GetAllDisciplineInvestigation(Resource):
    def post(self):
        payload = request.get_json()
        investigation_obj = InvetigationeService()
        return investigation_obj.get_all_discipline_investigation(payload['discipline_id'])

class RemoveInvestigation(Resource):
    def post(self):
        payload = request.get_json()
        investigation_obj = InvetigationeService()
        return investigation_obj.remove_investigation(payload['investigation_id'])


class GetAllDiscipline(Resource):

    def post(self):
        options = request.get_json()
        obj = DisciplineService()
        return obj.get_all_discipline(options)


class GetDisciplineData(Resource):

    def post(self):
        options = request.get_json()
        obj = DisciplineService()
        return obj.get_discipline_data(options["discipline_id"])

#Default member assessment
class CreateDefaultMemberAssessment(Resource):

    def post(self):
        payload = request.get_json()
        obj = DisciplineAssessmentService()
        return obj.create_default_member_assessment(payload)


class GetAllDefaultMemberAssessment(Resource):

    def post(self):
        payload = request.get_json()
        obj = DisciplineAssessmentService()
        return obj.get_all_default_member_assessment()

class GetDefaultMemberAssessmentBYDiscipline(Resource):

    def post(self):
        payload = request.get_json()
        obj = DisciplineAssessmentService()
        return obj.get_default_assessment_for_discipline(payload['discipline_id'])

class AddDefaultMemberAssessmentToDiscipline(Resource):

    def post(self):
        payload = request.get_json()
        obj = DisciplineAssessmentService()
        return obj.add_default_assessment_to_discipline(payload)

class CreateFormGroups(Resource):

    def post(self):
        payload = request.get_json()
        obj = FormGroupService()
        return obj.create_form_groups(payload)

class GetFormGroup(Resource):

    def post(self):
        payload = request.get_json()
        obj = FormGroupService()
        return obj.get_form_group_data(payload['form_group_id'])

class GetAllFormGroups(Resource):

    def post(self):
        payload = request.get_json()
        obj = FormGroupService()
        return obj.get_all_form_groups()

class UpdateFormGroup(Resource):

    def post(self):
        payload = request.get_json()
        form_group_id = payload['form_group_id']
        data = payload['data']
        obj = FormGroupService()
        return obj.update_form_group(form_group_id, data)

class RemoveFormGroup(Resource):

    def post(self):
        payload = request.get_json()
        form_group_id = payload['form_group_id']
        obj = FormGroupService()
        return obj.remove_form_group(form_group_id)

class AddFormGroupToDiscipline(Resource):

    def post(self):
        payload = request.get_json()
        obj = FormGroupService()
        return obj.add_formgroup_to_discipline_with_order(payload)
        # return obj.add_formgroup_to_discipline(payload)

class GetDisciplineTabs(Resource):

    def post(self):
        payload = request.get_json()
        discipline_id = payload['discipline_id']
        obj = FormGroupService()
        return obj.get_discipline_tab(discipline_id)



class RemoveFormGroupFromDiscipline(Resource):

    def post(self):
        payload = request.get_json()
        form_group_id = payload['form_group_id']
        discipline_id = payload['discipline_id']
        obj = FormGroupService()
        return obj.remove_formgroup_from_discipline(form_group_id, discipline_id)

class CreateProductHouse(Resource):

    def post(self):
        payload = request.get_json()
        obj = ProductHouseService()
        return obj.create_product_house(payload)

class CreateProduct(Resource):

    def post(self):
        payload = request.get_json()
        obj = ProductHouseService()
        return obj.create_product(payload)

class GetAllProductHouse(Resource):

    def post(self):
        payload = request.get_json()
        obj = ProductHouseService()
        return obj.get_alll_producthouse()

class RemoveProductHouse(Resource):

    def post(self):
        payload = request.get_json()
        obj = ProductHouseService()
        return obj.remove_product_house(payload['product_house_id'])

#==============================
class GetProductByProductHouse(Resource):

    def post(self):
        payload = request.get_json()
        obj = ProductHouseService()
        return obj.get_product_by_product_house(payload['product_house_id'])

class RemoveProductFromProductHouse(Resource):

    def post(self):
        payload = request.get_json()
        obj = ProductHouseService()
        return obj.remove_product_from_house(payload)

class AddProductToBizorg(Resource):

    def post(self):
        payload = request.get_json()
        obj = ProductHouseService()
        return obj.add_product_to_bizorg(payload)

class GetProductBizorgTree(Resource):

    def post(self):
        payload = request.get_json()
        obj = ProductHouseService()
        return obj.get_product_bizorg_tree(payload)

class RemoveProductFromBizorg(Resource):

    def post(self):
        payload = request.get_json()
        obj = ProductHouseService()
        return obj.remove_product_from_bizorg(payload['product_id'],payload['bizorg_id'])

class GetAllBizorg(Resource):

    def post(self):
        payload = request.get_json()
        obj = CorporateData()
        return obj.get_all_bizorg()

class GetProductByBizorg(Resource):

    def post(self):
        payload = request.get_json()
        bizorg_id = payload['bizorg_id']
        obj = ProductHouseService()
        return obj.get_product_by_bizorg(bizorg_id)


class SaveFormgroupAnswer(Resource):
    def post(self):
        payload = request.get_json()
        form_id = payload['form_id']
        prescription_id = payload['prescription_id']
        form_data = payload['form_data']
        answer_data = payload['answer_data']
        obj = PrescriptionService()
        return obj.add_form_answer_to_priscription(form_id,prescription_id,form_data,answer_data)

class GetFormgroupAnswer(Resource):
    def post(self):
        payload = request.get_json()
        form_id = payload['form_id']
        prescription_id = payload['prescription_id']
        obj = PrescriptionService()
        return obj.get_formgroup_answers(form_id,prescription_id)

class GetBookingTransactionDetail(Resource):
    def post(self):
        payload = request.get_json()
        booking_transaction_id = payload['booking_transaction_id']
        obj = BookingTransactionHistory()
        return obj.get_transaction_detail(booking_transaction_id)


class CreateClassificationExtensionJsonData(Resource):
    def post(self):
        payload = request.get_json()
        classification_id = payload['classification_id']
        data = payload['data']
        obj = ClassificationServices()
        return obj.create_classification_extension(classification_id,data)

class GetClassificationExtensionJsonData(Resource):
    def post(self):
        payload = request.get_json()
        classification_id = payload['classification_id']
        obj = ClassificationServices()
        return obj.get_classification_extension(classification_id)

class GetClassificationValueDataDropdownV2(Resource):
    def post(self):
        payload = request.get_json()
        obj = ClassificationServices()
        return obj.get_classification_value_data_dropdown_v2(payload)


class VerifyIndividualProviderEmail(Resource):

    def post(self):
        payload = request.get_json()
        obj = IndividualProviderServices()
        return obj.verify_provider_email(payload)



