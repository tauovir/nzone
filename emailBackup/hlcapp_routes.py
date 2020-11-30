from flask_restful import reqparse, abort, Api, Resource
from HLCAPP.dbserver.flask_app import api
from hlcapp_resource import *


api.add_resource(Foo, '/foo')
api.add_resource(Bar, '/bar')
api.add_resource(Search, '/search')     #Added errCode
api.add_resource(SearchProvider, '/search_provider')    #Added errCode
# api.add_resource(Login, '/login')
api.add_resource(GetTree, '/get_tree_biz')
api.add_resource(RemoveDivision, '/remove_division')
api.add_resource(GetDivisionEmployees, '/get_div_employees')
api.add_resource(GetEmployeesDivision, '/get_employee_divs') #Added errCode
api.add_resource(GetDivorgWithLevel, '/divorg_with_level')
api.add_resource(GetClassificationTree, '/get_classification_tree')
api.add_resource(DeleteClassification, '/remove_classification')
api.add_resource(GetClassificationValueDropdown, '/get_classification_value_data_dropdown')
api.add_resource(AddSubclassification, '/add_subclassification')
api.add_resource(CreateClassificationType, '/create_classification_type')
api.add_resource(UpdateAllowOther, '/update_other_classification_type')
api.add_resource(GetClassificationValueRecord, '/get_classification_value_record')


api.add_resource(AddProvider, '/add_provider')
api.add_resource(AddMember, '/add_member')
# api.add_resource(AddEmployeeNonCore, '/add_employee')
# api.add_resource(AddEmployeeFromOutsideNonCore, '/add_employee_from_outside')
# api.add_resource(AddEmployeeFromOutside, '/add_employee_from_outside')
api.add_resource(CheckEmail, '/check_user_email')
api.add_resource(GetDivisionsWithPractitioners, '/get_div_tree_with_practitioner')
api.add_resource(GetPersonInBizOrg, '/get_biz_person')  #Added errCode

api.add_resource(GetIndividualPracTree, '/get_div_tree_with_practitioner_individual')#Added errCode

api.add_resource(SendRegistrationMail, '/send_registration_email')
api.add_resource(CheckToken, '/confirm_provider_email')
api.add_resource(SendMemberRegisterMail, '/send_member_register_mail')
api.add_resource(ResendOTP, '/resend_otp')
api.add_resource(CheckOtp, '/confirm_otp')

api.add_resource(PushEmailToQueue, '/push_email_queue')

api.add_resource(CheckMemberRegistrationToken, '/confirm_member_register_mail')

api.add_resource(ResetPassword, '/reset_password')
api.add_resource(ValidateResetPassword, '/validate_reset_password_token')
api.add_resource(UpdatePassword, '/update_password')

api.add_resource(SendPassGenEmail, '/auto_generate_password')

api.add_resource(LocationSearch, '/search_location')
api.add_resource(MatchAddress, '/match_and_populate_address')

api.add_resource(GetNearestProviders, '/practitioner_location_search')

api.add_resource(CreateGroup, '/create_group')
api.add_resource(AllocateGroupToProvider, '/allocate_group_to_provider')
api.add_resource(AllocateGroupToPractitioner, '/allocate_group_to_practitioner')
api.add_resource(AllocateGroupToMultiPractitioner, '/allocate_group_to_multi_prac')



# api.add_resource(GetGroupDetails, '/get_group_details')
api.add_resource(SearchGroup, '/search_group')
api.add_resource(GetPersonInGroup, '/get_person_in_group')
api.add_resource(GetPersonInGroupV2, '/get_person_in_group/v2')
api.add_resource(AddPersonToGroup, '/add_person_to_group')
api.add_resource(AddAssessmentToGroup, '/add_assessments_to_group')
api.add_resource(ExtendAssessmentToPersons, '/extend_assessments_to_persons')

# api.add_resource(AddPersonToDivNonCore, '/add_person_to_div')
# api.add_resource(RemovePersonFromDivNonCore, '/remove_person_from_div')
# api.add_resource(GetAllChild,'/get_all_child')
# api.add_resource(GetAllParent,'/get_all_parent')

api.add_resource(LinkMemberProvider, '/link_member_provider')

api.add_resource(GetAllEmployees, '/get_all_employees')
api.add_resource(GetFile, '/get_file')
api.add_resource(GetDocumentsList, '/get_documents_list')
api.add_resource(AddScheduleNonCore, '/add_schedule/non-core')
api.add_resource(AddPractitioner, '/add_practitioner')

api.add_resource(GetAllPractitioner, '/get_all_practitioner')
api.add_resource(AddPractitionerToDivision, '/add_practitioner_to_division')
api.add_resource(GetPractitionersDivision, '/get_practitioner_divs')
api.add_resource(RemovePractitionerFromDiv, '/remove_practitioner_from_div')

api.add_resource(GetAllLocations, '/get_all_locations')

# api.add_resource(CheckBookingSlot, '/check_booking_slot_status')        #Unused
api.add_resource(UpdateBookingNonCore, '/update_booking/non-core')
api.add_resource(GetBooking, '/get_booking')
api.add_resource(GetDataForCancelBooking, '/v1/get_data_for_cancel_booking')
api.add_resource(CancelBooking, '/v1/cancel_booking')

api.add_resource(CheckPractitionerEmail, '/check_practitioner_email')
api.add_resource(SendPractitionerJoinRequest, '/send_practitioner_join_request')
api.add_resource(AcceptPractitionerInvite, '/acccept_practitioner_invite')

api.add_resource(GetAllMultispecialty, '/v1/get_all_multispecialty')
api.add_resource(AddAssessment, '/add_assessment')
# api.add_resource(SubmitAssessment, '/submit_assessment')
api.add_resource(GetAssessment, '/get_assessment')                      #unused

api.add_resource(LoginV2, '/login_v2')

# api.add_resource(APIRemoved, '/get_all_biz_id')
api.add_resource(GetAllAssessment, '/get_all_assessments')
api.add_resource(CopyAssessment, '/copy_assessment')
# api.add_resource(PublishAssessment, '/publish_assessment')          #unused
api.add_resource(GetGroups, '/get_all_groups')                          #Unused, probably
api.add_resource(GetAllSchedule, '/get_all_schedule')
api.add_resource(GetAttemptedAnswerCount, '/get_attempted_answer_count')
api.add_resource(CheckAttemptedStatus, '/check_assessment_attempt_status')
api.add_resource(ChangeAssessmentAnswerStatus, '/change_assessment_attempt_status1')
api.add_resource(ViewAssessmentAnswersData, '/view_assessment_answers_data')
api.add_resource(UseAssessment, '/use_assessment')

api.add_resource(GetPractitioner, '/get_practitioner')
# api.add_resource(AddSchduleSlotsRec, '/save_week_list')
api.add_resource(GetPersonData, '/get_persons_list')
api.add_resource(SaveAssessment, '/save_assessment')
api.add_resource(GetAssessmentReport, '/get_assessment_report')
api.add_resource(GetMembers, '/get_members')
api.add_resource(UploadFile,'/upload_file')
api.add_resource(UseDocumentService, '/use_document_service')
api.add_resource(AddEmployeeFromFile, '/add_employee_from_file')
api.add_resource(GetAllClassificationType, '/get_all_classification_type')

api.add_resource(UpdateProviderDetails, '/update_provider_details')
api.add_resource(DeactivateIndividualDivision, '/deactivate_individual_division')
api.add_resource(GetAllIndividualProvider, '/get_all_individual_providers')
api.add_resource(AddProviderDivision, '/add_provider_division')
api.add_resource(UpdatePractitionerDetails, '/update_practitioner')
api.add_resource(GetBookingValidation, '/booking_validation')
api.add_resource(CreateVirtualClinic, '/create_virtual_clinic')
api.add_resource(BlockSlotNonCore, '/block_slot/non-core')
api.add_resource(GetRoles, '/get_roles')
api.add_resource(CreateRole, '/create_role')
api.add_resource(GetSidebar, '/get_sidebar')
api.add_resource(UpdateSidebar, '/update_sidebar')
api.add_resource(GetComponents, '/get_components')
api.add_resource(UpdateComponentsData, '/update_components')
# api.add_resource(SearchUser, '/search_user_rec')
api.add_resource(AddDashboardToAssessment, '/add_dashboard_to_assessment')
api.add_resource(SearchUserFuzzy, '/user_search')

api.add_resource(RefreshMatView, '/refresh_mat_view')
api.add_resource(GetLoyaltyAudit, '/_get_loyality_audit')
api.add_resource(GetNavbarData, '/get_navbar')
api.add_resource(UpdateNavbarData, '/update_navbar')
api.add_resource(GetPaymentDetails, '/payment')
api.add_resource(GetPaymentStatus, '/payment_status')
api.add_resource(CreateAnalyticsView, '/create_refresh_analytics_view')
api.add_resource(CreateAutomaticDashboard, '/create_automatic_dashboard')
api.add_resource(CreateUpdateBelt, '/create_update_belt')
api.add_resource(SwitchUserRole, '/switch_user_role')
api.add_resource(GetBizOrg, '/biz_org')

api.add_resource(GetAllAssessmentRoles, '/get_all_assessment_roles')
api.add_resource(GetAssessmentsForCorporate, '/get_assessments_for_corporate')
api.add_resource(GetAssessmentsAttemptedForCorporate, '/get_assessments_attemped_for_corporate')
api.add_resource(GetAssessmentsForPersonWithProvider, '/get_assessments_for_person_with_provider/v1')
api.add_resource(GetAssessmentsDatesForPersonWithProvider, '/get_assessments_dates_for_person_with_provider/v1')
api.add_resource(CreatePerson, '/create_person')
api.add_resource(GetAssessmentDates, '/get_assessment_dates')
api.add_resource(GetAttemptedAnswerCountV2, '/get_answer_attempt_countV2')
api.add_resource(AssessmentProviderBookingDetails, '/get_assessment_provider_booking_details')


#Groups Get Services
api.add_resource(GetAllGroupRoles, '/get_all_group_roles')
api.add_resource(GetAllGroupRolesWithProviders, '/get_all_group_roles_with_providers')
api.add_resource(GetMPGGroupRoles, '/get_mpg_group_roles')
api.add_resource(GetPatientGroupsForProvider, '/get_patient_groups_for_provider')


api.add_resource(AllocateRole, '/allocate_role')            #To Be removed from frontend
api.add_resource(BreadcrumbService, '/breadcrumb_service')
api.add_resource(SendAssessmentReport, '/mail_assessment_report')
api.add_resource(InsertChatFriendsBooking, '/insert_chat_friends_booking')
api.add_resource(CometChatUserMessage, '/get_comet_chat_user_message')
api.add_resource(GetBookingHistory, '/get_booking_history')
api.add_resource(GetUsersRoles, '/get_users_roles')
api.add_resource(UpdateUserRoles, '/update_user_roles')
api.add_resource(GetAllEngagmentRoles, '/get_all_engagement_role')
api.add_resource(SaveEngagmentJSON, '/save_engagement')
api.add_resource(GetEngagement, '/load_engagement')
api.add_resource(UpdateEngagement, '/update_engagement')
api.add_resource(GetEngagementMembers, '/get_engagement_members')
api.add_resource(GetEngagementInstance, '/get_engagement_instance')
api.add_resource(AlllocateEngagement, '/allocate_engagement_to_group')
api.add_resource(ExtendEngagement, '/extend_engagement')

api.add_resource(GetAllVideos, '/get_all_videos')
api.add_resource(AddVideo, '/add_video')
api.add_resource(UpdateVideo, '/update_video')

api.add_resource(GetAllEvents, '/get_all_events')
api.add_resource(AddEvent, '/add_event')
api.add_resource(PublishEvent, '/publish_event')
api.add_resource(GetEventsSchedule, '/get_event_schedule')
api.add_resource(CheckEventSlot, '/check_event_availability')
api.add_resource(BookEvent, '/book_event_for_person')
api.add_resource(GetEventPersonList, '/get_event_persons_list')
api.add_resource(MarkEventAttendance, '/mark_event_attendance')
api.add_resource(MarkIndividualAttendance, '/mark_individual_attendance')

api.add_resource(GetAssessmentGroupRec, '/get_assessment_group_rec')
api.add_resource(CompleteVideo, '/complete_engagement_video')
api.add_resource(GetEventsRoles, '/get_user_events')

api.add_resource(GetAllMultispecialtySchedule, '/get_all_multispecialty_schedule')
api.add_resource(GetInternalProvidersEngagement, '/get_internal_providers_engagement')
# api.add_resource(GetDatetimes, '/get_datetimes')
api.add_resource(GetEngagementKeys, '/get_engagement_keys')
api.add_resource(PublishCorporateEvent, '/publish_corporate_event')
api.add_resource(GetCorporateEventParticipants, '/get_corporate_event_participants')
api.add_resource(HandleEventInvitation, '/handle_event_invitation')
api.add_resource(UpdateEventInviteStatus, '/update_event_invitation')
api.add_resource(UpdateEventInvitePerson, '/update_event_invite_person')
api.add_resource(GetCorporateEventParticipantsData, '/get_corporate_event_participant_data')
api.add_resource(UpdateFeedback, '/update_feedback')
api.add_resource(AddNonMembersToEvent, '/add_non_members_to_event')
api.add_resource(GetAllAssessmentEvents, '/get_all_assessments_events')
api.add_resource(GetEventProvidersAssessments, '/get_events_providers_assessments')
api.add_resource(GetEventRec, '/get_event_rec')
api.add_resource(SendFeedbackEmail, '/event_feedback_email')
api.add_resource(GetAssessmentMetaData, '/get_assessment_metadata')

api.add_resource(UpdateCorporateEvent, '/update_corporate_event')
api.add_resource(UpdateDivisionData, '/update_division_data')

api.add_resource(GetProfileDetails, '/get_user_details')
api.add_resource(UpdateUserProfile, '/update_user_details')
api.add_resource(DataTablePreview, '/data_table_preview')
api.add_resource(GetOtherClassifications, '/get_other_classifications')
api.add_resource(AllInternalProviderSchedue, '/all_internal_provider_schedule')
api.add_resource(InternalPractitionerLocations, '/all_internal_provider_locations')
api.add_resource(AddOtherClassification, '/add_other_classification')
# api.add_resource(DeleteEmployeeNonCore, '/delete_employee')
api.add_resource(GetDeletedEmployees, '/get_deleted_employees')
api.add_resource(UseOtherClassification, '/use_other_classification')
api.add_resource(CreateInquiry, '/create_inquiry')
api.add_resource(GetAllInquiries, '/get_all_inquiries')
api.add_resource(UpdateInquiry, '/update_inquiry')
api.add_resource(GetWidgetsForRoles, '/get_widgets_for_roles')
api.add_resource(GetHomepageWidgets, '/get_homepage_widgets')
api.add_resource(SaveUserWidgets, '/save_user_widgets')
api.add_resource(PromoteEmployeeToUser, '/promote_employee_to_use')
api.add_resource(GetClassBookings, '/get_class_bookings')
api.add_resource(ViewUpdateEmployeeNonCore, '/view_update_employee')
api.add_resource(ViewPractitionerDetails, '/view_practitioner_details')
api.add_resource(GetProviderData, '/get_provider_data')



api.add_resource(AddEmployee, '/add_employee')
api.add_resource(AddEmployeeFromOutside, '/add_employee_from_outside')
api.add_resource(AddPersonToDiv, '/add_person_to_div')
api.add_resource(RemovePersonFromDiv, '/remove_person_from_div')
api.add_resource(DeleteEmployee, '/delete_employee')
# api.add_resource(ViewUpdateEmployee, '/view_update_employee')


api.add_resource(AddSchedule, '/add_schedule')
api.add_resource(BlockSlot, '/block_slot')
api.add_resource(UpdateBooking, '/update_booking')


# Bulk assessment endpoints
api.add_resource(GetAssessmentData, '/get_all_assessment_data')


# Person details to show above assessment
api.add_resource(GetPersonDetails, '/get_person_details')

# Email services
api.add_resource(GetAllEmailContent, '/get_all_emails')
api.add_resource(GetAllEmailContentSingle, '/get_single_email')
api.add_resource(AddEmailContent, '/add_email_content')
api.add_resource(UpdateEmailContent, '/update_email_content')

#Notification Log Services
api.add_resource(AddEmailLog, '/email_log')


api.add_resource(MPGTree, '/get_mpg_tree_with_divisions')

#Provider View Data API
api.add_resource(ProviderViewDataAPI, '/view/provider_view_data_query')


api.add_resource(AssessmentDataOfflineMPG, '/view/get_assessment_data_offline_using_mpg')
api.add_resource(UploadOfflineAssessmentDataForMPG, '/view/upload_assessment_data_offline_using_mpg')
api.add_resource(ProcessDataJson, '/view/process_data_json')
api.add_resource(GetAllOfflineDataJson, '/view/get_all_offline_data_json')
api.add_resource(AllowAttemptOnlineForMPG, '/view/allow_attempt_online')
api.add_resource(CreateCorporateCustomerObj, '/create_corporate_customer')
api.add_resource(AddCorporateCustomerDivisionObj, '/add_corporate_customer_division')
#=========Corporate Employee Audit Data===============
api.add_resource(CorporateCustomerEmployeeAuditData, '/corporate_customer_employee_audit')
#============Priovider================
api.add_resource(CreateProviderShareLink, '/create_provider_share_link')
api.add_resource(ProviderSharableLink, '/get_provider_division_sharable_link')
api.add_resource(ProviderDivisions, '/get_provider_divisions')


#upload corporate Logo:
api.add_resource(UploadCorporateLogo, '/upload_corporate_logo')
api.add_resource(GetCorporateLogo, '/get_corporate_logo')
#===========Transaction History==========
api.add_resource(BookingTransactionData, '/booking_transaction_data')

#=======================Consultation=================
api.add_resource(MedicineDiscipline, '/consultation/get_all_medicines')

api.add_resource(AssessmentDisciplineMember, '/consultation/get_all_assessment_member')
api.add_resource(AssessmentDisciplineProvider, '/consultation/get_all_assessment_provider')
# api.add_resource(GetInvestigationByType, '/consultation/get_investigation_by_type') # This is not being used
api.add_resource(GetMemberDetailsConsultation, '/consultation/get_member_details')
api.add_resource(GetProviderDetailsConsultation, '/consultation/get_provider_details')
#============Feedback================
api.add_resource(MemberFeedback, '/booking/add_member_feedback')
api.add_resource(GetMemberFeedback, '/booking/get_member_feedback')


#===========Prescription=================
api.add_resource(CreatePrescription, '/create_prescription')
api.add_resource(UpdatePrescription, '/update_prescription')
api.add_resource(AddPrescriptionMedicine, '/add_prescription_medicine')
api.add_resource(GetPrescriptionMedicine, '/get_prescription_medicine')
api.add_resource(AddPrescriptionInvestigation, '/add_prescription_investigation')
api.add_resource(GetPrescriptionInvestigation, '/get_prescription_investigation')
api.add_resource(AddPrescriptionProcedure, '/add_prescription_procedure')
api.add_resource(GetPrescriptionProcedure, '/get_prescription_procedure')
api.add_resource(GetPrescriptionData, '/get_prescription_data')

api.add_resource(AddPrescriptionNotes, '/add_prescription_notes')
api.add_resource(CompletePrescription, '/complete_prescription')
api.add_resource(AddReferallToInvestigation, '/add_referall_to_investigation')
api.add_resource(AddPrescriptionReferal, '/add_referal_to_prescription')
api.add_resource(AddPrescriptionAssessmentMember, '/add_prescription_assessment_member')
api.add_resource(GetPrescriptionAssessmentMember, '/get_prescription_assessment_member')
api.add_resource(AddPrescriptionAssessmentProvider, '/add_prescription_assessment_provider')
api.add_resource(GetPrescriptionAssessmentProvider, '/get_prescription_assessment_provider')
api.add_resource(GetPrescriptionNotes, '/get_prescription_notes')
api.add_resource(GetPrescriptionDetailDoc, '/get_prescription_detail_doc')

#============Upload Member Document=============
api.add_resource(UploadMemberDocuments, '/upload_booking_member_documents')
api.add_resource(GetMemberDocuments, '/get_booking_member_documents')
#================Discipline Assessment================
api.add_resource(CreateDisciplineAssessment, '/consultation_data/create_discipline_assessment')
api.add_resource(GetAllProviderAssessments, '/consultation_data/get_all_provider_assessments')
api.add_resource(GetProviderAssessmentData, '/consultation_data/get_provider_assessment_data')
api.add_resource(DeactivateDisciplineAssessment, '/consultation_data/deactivate_discipline_assessment')
api.add_resource(GetAllDiscplineProvider, '/consultation_data/get_all_discipline_provider')
#==============Medicine Api============
api.add_resource(GetAllMedicines, '/medicine/get_all_medicines')
api.add_resource(CreateMedicine, '/medicine/create_medicine')
api.add_resource(RemoveMedicine, '/medicine/remove_medicine')
api.add_resource(AddMedicineToDiscipline, '/medicine/add_medicine_to_discipline')

#==============Discipline Api============
api.add_resource(CreateDiscipline, '/discipline/create_discipline')
api.add_resource(UpdateDiscipline, '/discipline/update_discipline')
api.add_resource(GetAllDiscipline, '/discipline/get_all_discipline')
api.add_resource(GetDisciplineData, '/discipline/get_discipline_data')

#==================Investigation Procedure  API=================

api.add_resource(CreateProcedure, '/investigation/create_procedure')
api.add_resource(GetAllProcedure, '/investigation/get_all_procedure')
api.add_resource(GetProcedureData, '/investigation/get_procedure_data')
api.add_resource(RemoveProcedure, '/investigation/remove_procedure')
api.add_resource(GetAllDisciplineProcedure, '/investigation/get_all_discipline_procedure')
api.add_resource(AddProcedureToDiscpline, '/investigation/add_procedure_to_discipline')

#===========================Investigation API==================
api.add_resource(CreateInvetigation, '/investigation/create_investigation')
api.add_resource(GetAllInvestigation, '/investigation/get_all_investigation')
api.add_resource(GetAllInvestigationTree, '/get_investigation_tree')
api.add_resource(AddInvestigationToDiscpline, '/investigation/add_investigation_to_discipline')
api.add_resource(GetAllDisciplineInvestigation, '/investigation/get_all_discipline_investigation')
api.add_resource(RemoveInvestigation, '/investigation/remove_investigation')
# api.add_resource(GetInvestigationData, '/investigation/get_investigation_data')
# api.add_resource(UpdateInvestigation, '/investigation/update_investigation') # Check this
#==========================Default member assessment==================
api.add_resource(CreateDefaultMemberAssessment, '/default_member_assessment/create_default_member_assessment')
api.add_resource(GetAllDefaultMemberAssessment, '/default_member_assessment/get_all_default_member_assessment')
api.add_resource(GetDefaultMemberAssessmentBYDiscipline, '/default_member_assessment/get_default_member_assessment_by_discipline')
api.add_resource(AddDefaultMemberAssessmentToDiscipline, '/default_member_assessment/add_default_member_assessment_to_discipline')

#===========Form Groups==========================
api.add_resource(CreateFormGroups, '/form_groups/create_form_group')
api.add_resource(GetFormGroup, '/form_groups/get_form_group')
api.add_resource(GetAllFormGroups, '/form_groups/get_all_form_groups')
api.add_resource(UpdateFormGroup, '/form_groups/update_form_group')
api.add_resource(RemoveFormGroup, '/form_groups/remove_form_group')

api.add_resource(AddFormGroupToDiscipline, '/discipline/add_form_group_to_discipline')
api.add_resource(GetDisciplineTabs, '/discipline/get_discipline_tabs')
api.add_resource(RemoveFormGroupFromDiscipline, '/discipline/remove_form_group_from_discipline')

#=================formgroup ans===============
api.add_resource(SaveFormgroupAnswer, '/prescription/save_formgroup_answer')
api.add_resource(GetFormgroupAnswer, '/prescription/get_formgroup_answer')

#================Pdoduct house====================
api.add_resource(CreateProductHouse, '/product/create_product_house')
api.add_resource(CreateProduct, '/product/create_product')
api.add_resource(GetAllProductHouse, '/product/get_all_product_house')
api.add_resource(RemoveProductHouse, '/product/remove_product_house')


api.add_resource(GetProductByProductHouse, '/product/get_product_by_product_house')
api.add_resource(RemoveProductFromProductHouse, '/product/remove_product_from_product_house')
api.add_resource(AddProductToBizorg, '/product/add_product_to_bizorg')
api.add_resource(GetProductBizorgTree, '/product/get_product_bizorg_tree')
api.add_resource(RemoveProductFromBizorg, '/product/remove_product_from_bizorg')
api.add_resource(GetAllBizorg, '/get_all_bizorg')
api.add_resource(GetProductByBizorg, '/product/get_product_by_bizorg')

#==========================Booking Transaction==========
api.add_resource(GetBookingTransactionDetail, '/get_booking_transaction_detail')

#====================Classification_extension================
api.add_resource(CreateClassificationExtensionJsonData, '/create_classification_extension_data')
api.add_resource(GetClassificationExtensionJsonData, '/get_classification_extension_data')
api.add_resource(GetClassificationValueDataDropdownV2, '/get_classification_value_data_dropdown_v2')
#===========Provider Email verification=====================
api.add_resource(VerifyIndividualProviderEmail, '/verify_individual_provider_email')



