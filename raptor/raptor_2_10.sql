PGDMP     9         
            x            raptor_01_10 "   10.14 (Ubuntu 10.14-1.pgdg20.04+1) #   12.5 (Ubuntu 12.5-0ubuntu0.20.04.1) �   �           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false            �           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false            �           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false            �           1262    313013    raptor_01_10    DATABASE     r   CREATE DATABASE raptor_01_10 WITH TEMPLATE = template0 ENCODING = 'UTF8' LC_COLLATE = 'en_IN' LC_CTYPE = 'en_IN';
    DROP DATABASE raptor_01_10;
                postgres    false                        2615    313014    leggero    SCHEMA        CREATE SCHEMA leggero;
    DROP SCHEMA leggero;
                admin    false                        3079    313015    pg_trgm 	   EXTENSION     ;   CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;
    DROP EXTENSION pg_trgm;
                   false            �           0    0    EXTENSION pg_trgm    COMMENT     e   COMMENT ON EXTENSION pg_trgm IS 'text similarity measurement and index searching based on trigrams';
                        false    2            �            1259    313080    Communication_Templates    TABLE     �   CREATE TABLE leggero."Communication_Templates" (
    id integer NOT NULL,
    name character varying,
    description character varying,
    data jsonb,
    status boolean,
    type character varying,
    has_params boolean
);
 .   DROP TABLE leggero."Communication_Templates";
       leggero            postgres    false    5            �            1259    313086    Communication_Templates_id_seq    SEQUENCE     �   ALTER TABLE leggero."Communication_Templates" ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME leggero."Communication_Templates_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);
            leggero          postgres    false    198    5            �            1259    313088    api_definition    TABLE     �  CREATE TABLE leggero.api_definition (
    id integer NOT NULL,
    api_name character varying,
    api_type character varying,
    input_json jsonb,
    output_json jsonb,
    status boolean,
    api_definition2project integer,
    create_datetime timestamp without time zone,
    lastchange_datetime timestamp without time zone,
    input_json_map jsonb,
    output_json_map jsonb,
    api2auth_id integer,
    authentication_json jsonb,
    api_configuration_json jsonb
);
 #   DROP TABLE leggero.api_definition;
       leggero            postgres    false    5            �            1259    313094    api_definition_id_seq    SEQUENCE     �   CREATE SEQUENCE leggero.api_definition_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 -   DROP SEQUENCE leggero.api_definition_id_seq;
       leggero          postgres    false    200    5            �           0    0    api_definition_id_seq    SEQUENCE OWNED BY     Q   ALTER SEQUENCE leggero.api_definition_id_seq OWNED BY leggero.api_definition.id;
          leggero          postgres    false    201            �            1259    313096    api_writer_audit    TABLE     L  CREATE TABLE leggero.api_writer_audit (
    id integer NOT NULL,
    api_writer_audit2node_instance integer,
    input_json jsonb,
    output_json jsonb,
    api_writer_audit2pipe_ins integer,
    create_datetime timestamp without time zone NOT NULL,
    api_writer_audit2api_writer integer,
    record_pointer character varying
);
 %   DROP TABLE leggero.api_writer_audit;
       leggero            postgres    false    5            �            1259    313102    api_writer_audit_id_seq    SEQUENCE     �   ALTER TABLE leggero.api_writer_audit ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME leggero.api_writer_audit_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);
            leggero          postgres    false    5    202            �            1259    313104    at_email_configuration    TABLE     e  CREATE TABLE leggero.at_email_configuration (
    id integer NOT NULL,
    at2parent_object integer NOT NULL,
    app_username character varying NOT NULL,
    db_username character varying NOT NULL,
    insert_date date NOT NULL,
    insert_time time without time zone NOT NULL,
    changes jsonb NOT NULL,
    change_type character varying(20) NOT NULL
);
 +   DROP TABLE leggero.at_email_configuration;
       leggero            postgres    false    5            �            1259    313110    at_email_configuration_id_seq    SEQUENCE     �   ALTER TABLE leggero.at_email_configuration ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME leggero.at_email_configuration_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);
            leggero          postgres    false    204    5            �            1259    313112    connections_con_id_seq    SEQUENCE     �   CREATE SEQUENCE leggero.connections_con_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 .   DROP SEQUENCE leggero.connections_con_id_seq;
       leggero          admin    false    5            �            1259    313114    connections    TABLE       CREATE TABLE leggero.connections (
    con_id bigint DEFAULT nextval('leggero.connections_con_id_seq'::regclass) NOT NULL,
    name character varying(45) NOT NULL,
    con_string character varying(200) NOT NULL,
    con_type character varying(45) NOT NULL
);
     DROP TABLE leggero.connections;
       leggero            admin    false    206    5            �            1259    313118    datasource_ds_id_seq    SEQUENCE     ~   CREATE SEQUENCE leggero.datasource_ds_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 ,   DROP SEQUENCE leggero.datasource_ds_id_seq;
       leggero          admin    false    5            �            1259    313120 
   datasource    TABLE     �  CREATE TABLE leggero.datasource (
    ds_id bigint DEFAULT nextval('leggero.datasource_ds_id_seq'::regclass) NOT NULL,
    name character varying(45) NOT NULL,
    ds_table character varying(45) NOT NULL,
    ftype character varying(45),
    connection_id bigint NOT NULL,
    partition_col character varying(45),
    lowerbound bigint,
    upperbound bigint,
    numpartitions bigint,
    predicates character varying(45),
    splitscheme text,
    col_list text,
    dep_stat character varying(45)
);
    DROP TABLE leggero.datasource;
       leggero            admin    false    208    5            �            1259    313127    db_writer_audit    TABLE     G  CREATE TABLE leggero.db_writer_audit (
    id integer NOT NULL,
    db_writer_audit2node_instance integer,
    input_json jsonb,
    output_json jsonb,
    create_datetime timestamp without time zone NOT NULL,
    db_writer_audit2pipe_ins integer,
    db_writer_audit2db_writer integer,
    record_pointer character varying
);
 $   DROP TABLE leggero.db_writer_audit;
       leggero            postgres    false    5            �            1259    313133    db_writer_audit_id_seq    SEQUENCE     �   ALTER TABLE leggero.db_writer_audit ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME leggero.db_writer_audit_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);
            leggero          postgres    false    5    210            �            1259    313135    dds_api_writer    TABLE     \  CREATE TABLE leggero.dds_api_writer (
    id integer NOT NULL,
    tablename character varying,
    api_writer2version integer,
    api_writer2api_id integer,
    input_json_map jsonb,
    api_writer_name character varying,
    status boolean,
    create_datetime timestamp without time zone,
    lastchange_datetime timestamp without time zone
);
 #   DROP TABLE leggero.dds_api_writer;
       leggero            postgres    false    5            �            1259    313141    dds_api_writer_id_seq    SEQUENCE     �   CREATE SEQUENCE leggero.dds_api_writer_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 -   DROP SEQUENCE leggero.dds_api_writer_id_seq;
       leggero          postgres    false    5    212            �           0    0    dds_api_writer_id_seq    SEQUENCE OWNED BY     Q   ALTER SEQUENCE leggero.dds_api_writer_id_seq OWNED BY leggero.dds_api_writer.id;
          leggero          postgres    false    213            �            1259    313143    dds_custom_functions    TABLE       CREATE TABLE leggero.dds_custom_functions (
    id integer NOT NULL,
    function_name character varying,
    function_string character varying,
    function_arguments character varying,
    function_info character varying,
    function2version integer,
    status boolean
);
 )   DROP TABLE leggero.dds_custom_functions;
       leggero            admin    false    5            �            1259    313149    dds_custom_functions_id_seq    SEQUENCE     �   ALTER TABLE leggero.dds_custom_functions ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME leggero.dds_custom_functions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);
            leggero          admin    false    214    5            �            1259    313151    dds_filter_functions    TABLE       CREATE TABLE leggero.dds_filter_functions (
    id integer NOT NULL,
    function_name character varying,
    function_string character varying,
    function_info character varying,
    function2version integer,
    status boolean,
    tablename character varying
);
 )   DROP TABLE leggero.dds_filter_functions;
       leggero            admin    false    5            �            1259    313157    dds_filter_functions_id_seq    SEQUENCE     �   CREATE SEQUENCE leggero.dds_filter_functions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 3   DROP SEQUENCE leggero.dds_filter_functions_id_seq;
       leggero          admin    false    5    216            �           0    0    dds_filter_functions_id_seq    SEQUENCE OWNED BY     ]   ALTER SEQUENCE leggero.dds_filter_functions_id_seq OWNED BY leggero.dds_filter_functions.id;
          leggero          admin    false    217            �            1259    313159    dds_ftp_definition    TABLE     �  CREATE TABLE leggero.dds_ftp_definition (
    id integer NOT NULL,
    host character varying NOT NULL,
    username character varying,
    password character varying,
    create_datetime timestamp without time zone,
    lastchange_datetime timestamp without time zone,
    ftp_def2project integer NOT NULL,
    name character varying,
    root_dir character varying,
    status character varying
);
 '   DROP TABLE leggero.dds_ftp_definition;
       leggero            postgres    false    5            �            1259    313165    dds_ftp_definition_id_seq    SEQUENCE     �   ALTER TABLE leggero.dds_ftp_definition ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME leggero.dds_ftp_definition_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);
            leggero          postgres    false    218    5            �            1259    313167    dds_global_imports    TABLE     �   CREATE TABLE leggero.dds_global_imports (
    id integer NOT NULL,
    function_name character varying,
    function_string character varying,
    function_info character varying,
    function2version integer,
    status boolean
);
 '   DROP TABLE leggero.dds_global_imports;
       leggero            admin    false    5            �            1259    313173    dds_global_imports_id_seq    SEQUENCE     �   CREATE SEQUENCE leggero.dds_global_imports_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 1   DROP SEQUENCE leggero.dds_global_imports_id_seq;
       leggero          admin    false    5    220            �           0    0    dds_global_imports_id_seq    SEQUENCE OWNED BY     Y   ALTER SEQUENCE leggero.dds_global_imports_id_seq OWNED BY leggero.dds_global_imports.id;
          leggero          admin    false    221            �            1259    313175    dds_mapping    TABLE     �   CREATE TABLE leggero.dds_mapping (
    id integer NOT NULL,
    mapping2dds_version integer,
    mapping_name character varying,
    mapping_configuration jsonb,
    status smallint
);
     DROP TABLE leggero.dds_mapping;
       leggero            postgres    false    5            �            1259    313181    dds_mapping_id_seq    SEQUENCE     �   CREATE SEQUENCE leggero.dds_mapping_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 *   DROP SEQUENCE leggero.dds_mapping_id_seq;
       leggero          postgres    false    5    222            �           0    0    dds_mapping_id_seq    SEQUENCE OWNED BY     K   ALTER SEQUENCE leggero.dds_mapping_id_seq OWNED BY leggero.dds_mapping.id;
          leggero          postgres    false    223            �            1259    313183    dds_pipe_ins_log_seq    SEQUENCE     �   CREATE SEQUENCE leggero.dds_pipe_ins_log_seq
    START WITH 1
    INCREMENT BY 1
    MINVALUE 0
    MAXVALUE 2147483647
    CACHE 1;
 ,   DROP SEQUENCE leggero.dds_pipe_ins_log_seq;
       leggero          postgres    false    5            �            1259    313185    dds_pipe_ins_log    TABLE     T  CREATE TABLE leggero.dds_pipe_ins_log (
    node_name character varying NOT NULL,
    start_time timestamp without time zone,
    end_time timestamp without time zone,
    input_json jsonb,
    output_json jsonb,
    pipe_ins_log2pipe_instance integer NOT NULL,
    completion_status character varying,
    error_status smallint,
    error_json jsonb,
    id integer DEFAULT nextval('leggero.dds_pipe_ins_log_seq'::regclass) NOT NULL,
    activity_type character varying(50),
    activity2report_config integer,
    activity2api_writer integer,
    activity2api_definition integer,
    activity2write_db integer,
    activity2version integer,
    node_type character varying(100),
    runtime_metadata jsonb,
    node_label character varying(100),
    create_datetime timestamp without time zone,
    lastchange_datetime timestamp without time zone
);
 %   DROP TABLE leggero.dds_pipe_ins_log;
       leggero            postgres    false    224    5            �           0    0 %   COLUMN dds_pipe_ins_log.activity_type    COMMENT     �   COMMENT ON COLUMN leggero.dds_pipe_ins_log.activity_type IS 'type of the activity ie.e. pipeline_log, report_config, api etc.';
          leggero          postgres    false    225            �           0    0 !   COLUMN dds_pipe_ins_log.node_type    COMMENT     n   COMMENT ON COLUMN leggero.dds_pipe_ins_log.node_type IS 'the type of node being run i.e. rebuildcolumn etc.';
          leggero          postgres    false    225            �           0    0 "   COLUMN dds_pipe_ins_log.node_label    COMMENT     u   COMMENT ON COLUMN leggero.dds_pipe_ins_log.node_label IS 'this is the label we enter while creating pipeline node.';
          leggero          postgres    false    225            ?           1259    314157    dds_pipe_ins_log_view    VIEW     x  CREATE VIEW leggero.dds_pipe_ins_log_view AS
 SELECT pl.node_name,
    pl.start_time,
    pl.end_time,
    pl.input_json,
    pl.output_json,
    pl.completion_status,
    pl.error_status,
    pl.error_json,
    pl.pipe_ins_log2pipe_instance AS pipeline_instance_id,
    pl.id,
    pl.node_label,
    pl.node_type,
    pl.runtime_metadata
   FROM leggero.dds_pipe_ins_log pl;
 )   DROP VIEW leggero.dds_pipe_ins_log_view;
       leggero          postgres    false    225    225    225    225    225    225    225    225    225    225    225    225    225    5            �            1259    313196    dds_pipeline_seq    SEQUENCE     �   CREATE SEQUENCE leggero.dds_pipeline_seq
    START WITH 1
    INCREMENT BY 1
    MINVALUE 0
    MAXVALUE 2147483647
    CACHE 1;
 (   DROP SEQUENCE leggero.dds_pipeline_seq;
       leggero          postgres    false    5            �            1259    313198    dds_pipeline    TABLE     <  CREATE TABLE leggero.dds_pipeline (
    name character varying NOT NULL,
    data_json jsonb NOT NULL,
    id integer DEFAULT nextval('leggero.dds_pipeline_seq'::regclass) NOT NULL,
    pipeline2version integer,
    create_datetime timestamp without time zone,
    lastchange_datetime timestamp without time zone
);
 !   DROP TABLE leggero.dds_pipeline;
       leggero            postgres    false    226    5            �            1259    313205    dds_pipeline_activity_defs_seq    SEQUENCE     �   CREATE SEQUENCE leggero.dds_pipeline_activity_defs_seq
    START WITH 1
    INCREMENT BY 1
    MINVALUE 0
    MAXVALUE 2147483647
    CACHE 1;
 6   DROP SEQUENCE leggero.dds_pipeline_activity_defs_seq;
       leggero          postgres    false    5            �            1259    313207    dds_pipeline_activity_defs    TABLE     �  CREATE TABLE leggero.dds_pipeline_activity_defs (
    id integer DEFAULT nextval('leggero.dds_pipeline_activity_defs_seq'::regclass) NOT NULL,
    api_name character varying(100) NOT NULL,
    api_url character varying(100) NOT NULL,
    status character varying(20) NOT NULL,
    api_description text,
    output_json_proto jsonb NOT NULL,
    activity_display_meta jsonb,
    activity_front_check_name text,
    input_json_frontend jsonb
);
 /   DROP TABLE leggero.dds_pipeline_activity_defs;
       leggero            postgres    false    228    5            A           1259    314166    dds_pipeline_activity_defs_view    VIEW     �  CREATE VIEW leggero.dds_pipeline_activity_defs_view AS
 SELECT dds_pipeline_activity_defs.id,
    dds_pipeline_activity_defs.api_name AS node_type,
    dds_pipeline_activity_defs.api_url AS url,
    dds_pipeline_activity_defs.status,
    dds_pipeline_activity_defs.output_json_proto,
    dds_pipeline_activity_defs.activity_display_meta,
    dds_pipeline_activity_defs.activity_front_check_name
   FROM leggero.dds_pipeline_activity_defs;
 3   DROP VIEW leggero.dds_pipeline_activity_defs_view;
       leggero          postgres    false    229    229    229    229    229    229    229    5            �            1259    313218     dds_pipeline_activity_params_seq    SEQUENCE     �   CREATE SEQUENCE leggero.dds_pipeline_activity_params_seq
    START WITH 1
    INCREMENT BY 1
    MINVALUE 0
    MAXVALUE 2147483647
    CACHE 1;
 8   DROP SEQUENCE leggero.dds_pipeline_activity_params_seq;
       leggero          postgres    false    5            �            1259    313220    dds_pipeline_instance_seq    SEQUENCE     �   CREATE SEQUENCE leggero.dds_pipeline_instance_seq
    START WITH 1
    INCREMENT BY 1
    MINVALUE 0
    MAXVALUE 2147483647
    CACHE 1;
 1   DROP SEQUENCE leggero.dds_pipeline_instance_seq;
       leggero          postgres    false    5            �            1259    313222    dds_pipeline_instance    TABLE     �  CREATE TABLE leggero.dds_pipeline_instance (
    pipeline_instance2pipeline integer NOT NULL,
    name character varying,
    start_time timestamp without time zone,
    end_time timestamp without time zone,
    instance_json jsonb,
    id integer DEFAULT nextval('leggero.dds_pipeline_instance_seq'::regclass) NOT NULL,
    times_trigger_run integer,
    create_datetime timestamp without time zone,
    lastchange_datetime timestamp without time zone
);
 *   DROP TABLE leggero.dds_pipeline_instance;
       leggero            postgres    false    231    5            E           1259    314183    dds_pipeline_instance_view    VIEW       CREATE VIEW leggero.dds_pipeline_instance_view AS
 SELECT pl.id AS pipeline_instance_id,
    pl.name,
    pl.pipeline_instance2pipeline AS pipeline_id,
    pl.start_time,
    pl.end_time,
    pl.id,
    pl.instance_json
   FROM leggero.dds_pipeline_instance pl;
 .   DROP VIEW leggero.dds_pipeline_instance_view;
       leggero          postgres    false    232    232    232    232    232    232    5            �            1259    313233    dds_pipeline_metadata_seq    SEQUENCE     �   CREATE SEQUENCE leggero.dds_pipeline_metadata_seq
    START WITH 1
    INCREMENT BY 1
    MINVALUE 0
    MAXVALUE 2147483647
    CACHE 1;
 1   DROP SEQUENCE leggero.dds_pipeline_metadata_seq;
       leggero          postgres    false    5            �            1259    313235    dds_project_versions    TABLE     �   CREATE TABLE leggero.dds_project_versions (
    id integer NOT NULL,
    version2project integer,
    name character varying,
    description character varying,
    version2parent_version integer,
    version_settings jsonb
);
 )   DROP TABLE leggero.dds_project_versions;
       leggero            admin    false    5            �            1259    313241    dds_projects    TABLE     �   CREATE TABLE leggero.dds_projects (
    id integer NOT NULL,
    name character varying,
    description character varying,
    project_settings jsonb
);
 !   DROP TABLE leggero.dds_projects;
       leggero            admin    false    5            @           1259    314161    dds_pipeline_view    VIEW     �  CREATE VIEW leggero.dds_pipeline_view AS
 SELECT pl.id AS pipeline_id,
    pl.name,
    pl.data_json,
    concat_ws(''::text, pl.id, dds_pr_v.id, dds_pr.id) AS id,
    dds_pr_v.name AS version_name,
    dds_pr.name AS project_name,
    dds_pr.id AS project_id,
    dds_pr_v.id AS version_id
   FROM ((leggero.dds_pipeline pl
     LEFT JOIN leggero.dds_project_versions dds_pr_v ON ((dds_pr_v.id = pl.pipeline2version)))
     LEFT JOIN leggero.dds_projects dds_pr ON ((dds_pr.id = dds_pr_v.version2project)));
 %   DROP VIEW leggero.dds_pipeline_view;
       leggero          postgres    false    227    227    227    227    234    234    234    235    235    5            �            1259    313252    dds_project_versions_id_seq    SEQUENCE     �   ALTER TABLE leggero.dds_project_versions ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME leggero.dds_project_versions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);
            leggero          admin    false    5    234            C           1259    314174    dds_project_versions_view    VIEW     �  CREATE VIEW leggero.dds_project_versions_view AS
 SELECT pr.id AS project_id,
    pr.name AS project_name,
    pr.description AS project_description,
    pr.project_settings,
    ver.id AS version_id,
    ver.name AS version_name,
    ver.description AS version_description,
    ver.version_settings,
    concat_ws(''::text, ver.id, pr.id) AS id
   FROM (leggero.dds_projects pr
     LEFT JOIN leggero.dds_project_versions ver ON ((ver.version2project = pr.id)));
 -   DROP VIEW leggero.dds_project_versions_view;
       leggero          postgres    false    234    234    234    234    234    235    235    235    235    5            �            1259    313258    dds_projects_id_seq    SEQUENCE     �   ALTER TABLE leggero.dds_projects ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME leggero.dds_projects_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);
            leggero          admin    false    235    5            �            1259    313260 
   dds_schema    TABLE     �   CREATE TABLE leggero.dds_schema (
    id smallint NOT NULL,
    schema jsonb,
    update_datetime timestamp without time zone,
    schema2project_version integer
);
    DROP TABLE leggero.dds_schema;
       leggero            admin    false    5            �            1259    313266    dds_schema_id_seq    SEQUENCE     �   ALTER TABLE leggero.dds_schema ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME leggero.dds_schema_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);
            leggero          admin    false    5    238            �            1259    313268    dds_script_definition    TABLE     �  CREATE TABLE leggero.dds_script_definition (
    id integer NOT NULL,
    name character varying NOT NULL,
    executor_path_id integer,
    script_path character varying,
    input_args character varying[],
    output_json jsonb,
    active boolean,
    script2project integer NOT NULL,
    create_datetime timestamp without time zone NOT NULL,
    lastchange_datetime timestamp without time zone NOT NULL,
    category character varying,
    script_code character varying NOT NULL
);
 *   DROP TABLE leggero.dds_script_definition;
       leggero            postgres    false    5            �            1259    313274    dds_script_definition_id_seq    SEQUENCE     �   ALTER TABLE leggero.dds_script_definition ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME leggero.dds_script_definition_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);
            leggero          postgres    false    5    240            �            1259    313276    dds_script_definition_instance    TABLE     �  CREATE TABLE leggero.dds_script_definition_instance (
    id integer NOT NULL,
    input_args character varying[] NOT NULL,
    output_json jsonb NOT NULL,
    start_datetime timestamp without time zone NOT NULL,
    end_datetime timestamp without time zone NOT NULL,
    process_id character varying NOT NULL,
    run_by character varying NOT NULL,
    script2master integer,
    status character varying,
    error_traceback character varying
);
 3   DROP TABLE leggero.dds_script_definition_instance;
       leggero            postgres    false    5            �            1259    313282 %   dds_script_definition_instance_id_seq    SEQUENCE     �   ALTER TABLE leggero.dds_script_definition_instance ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME leggero.dds_script_definition_instance_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);
            leggero          postgres    false    5    242            �            1259    313284    dds_script_executors    TABLE     �   CREATE TABLE leggero.dds_script_executors (
    id integer NOT NULL,
    name character varying NOT NULL,
    path character varying NOT NULL,
    active boolean
);
 )   DROP TABLE leggero.dds_script_executors;
       leggero            postgres    false    5            �            1259    313290    dds_script_executors_id_seq    SEQUENCE     �   ALTER TABLE leggero.dds_script_executors ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME leggero.dds_script_executors_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);
            leggero          postgres    false    244    5            9           1259    314128    dds_scripts_view    VIEW     G  CREATE VIEW leggero.dds_scripts_view AS
 SELECT script_execs.name AS executor_name,
    script_execs.path AS executor_path,
    script_def.id AS script_id,
    script_def.name,
    script_def.script_path,
    script_def.output_json,
    script_def.script2project,
    script_def.active,
    script_def.id,
    script_execs.id AS executor_path_id,
    script_def.category,
    script_def.input_args,
    script_def.script_code
   FROM (leggero.dds_script_definition script_def
     JOIN leggero.dds_script_executors script_execs ON ((script_def.executor_path_id = script_execs.id)));
 $   DROP VIEW leggero.dds_scripts_view;
       leggero          postgres    false    244    244    240    244    240    240    240    240    240    240    240    240    240    5            �            1259    313296    email_configuration    TABLE     �  CREATE TABLE leggero.email_configuration (
    id integer NOT NULL,
    email_id character varying NOT NULL,
    email_type character varying NOT NULL,
    server_type character varying(40),
    host character varying(40) NOT NULL,
    port integer NOT NULL,
    status character varying(20) NOT NULL,
    create_datetime timestamp without time zone NOT NULL,
    lastchange_datetime timestamp without time zone NOT NULL,
    password text NOT NULL,
    description text,
    name character varying NOT NULL,
    polling_on boolean,
    poll_frequency integer,
    app_username character varying NOT NULL,
    email_configuration2project integer
);
 (   DROP TABLE leggero.email_configuration;
       leggero            postgres    false    5            �           0    0 )   COLUMN email_configuration.poll_frequency    COMMENT     ]   COMMENT ON COLUMN leggero.email_configuration.poll_frequency IS 'poll_frequency in seconds';
          leggero          postgres    false    246            �            1259    313302    email_configuration_id_seq    SEQUENCE     �   ALTER TABLE leggero.email_configuration ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME leggero.email_configuration_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);
            leggero          postgres    false    246    5            �            1259    313304    email_read_param_config    TABLE     �  CREATE TABLE leggero.email_read_param_config (
    id integer NOT NULL,
    name character varying(200) NOT NULL,
    create_datetime timestamp without time zone NOT NULL,
    lastchange_datetime timestamp without time zone NOT NULL,
    status character varying(20) NOT NULL,
    description text,
    config_json jsonb NOT NULL,
    email_read_conf2email_config integer NOT NULL
);
 ,   DROP TABLE leggero.email_read_param_config;
       leggero            postgres    false    5            �            1259    313310    email_read_param_config_id_seq    SEQUENCE     �   ALTER TABLE leggero.email_read_param_config ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME leggero.email_read_param_config_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);
            leggero          postgres    false    5    248            �            1259    313312    lg_aofrmqry_id_seq    SEQUENCE     |   CREATE SEQUENCE leggero.lg_aofrmqry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 *   DROP SEQUENCE leggero.lg_aofrmqry_id_seq;
       leggero          admin    false    5            �            1259    313314    lg_aofrmqry    TABLE     �   CREATE TABLE leggero.lg_aofrmqry (
    id bigint DEFAULT nextval('leggero.lg_aofrmqry_id_seq'::regclass) NOT NULL,
    name character varying(45),
    dep_stat character varying(45),
    query_id bigint
);
     DROP TABLE leggero.lg_aofrmqry;
       leggero            admin    false    250    5            �            1259    313318    lg_columns_id_seq    SEQUENCE     {   CREATE SEQUENCE leggero.lg_columns_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 )   DROP SEQUENCE leggero.lg_columns_id_seq;
       leggero          admin    false    5            �            1259    313320 
   lg_columns    TABLE     �  CREATE TABLE leggero.lg_columns (
    id bigint DEFAULT nextval('leggero.lg_columns_id_seq'::regclass) NOT NULL,
    name character varying(200) NOT NULL,
    name_in_ds character varying(200) NOT NULL,
    filter_use bigint DEFAULT '1'::bigint NOT NULL,
    cast_type character varying(45) NOT NULL,
    decimals character varying(45),
    parent_id bigint NOT NULL,
    parent_type bigint DEFAULT '1'::bigint NOT NULL
);
    DROP TABLE leggero.lg_columns;
       leggero            admin    false    252    5            �            1259    313326    lg_composite_widget_seq    SEQUENCE     �   CREATE SEQUENCE leggero.lg_composite_widget_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    MAXVALUE 2147483647
    CACHE 1;
 /   DROP SEQUENCE leggero.lg_composite_widget_seq;
       leggero          postgres    false    5            �            1259    313328    lg_composite_widgets    TABLE     A  CREATE TABLE leggero.lg_composite_widgets (
    id bigint DEFAULT nextval('leggero.lg_composite_widget_seq'::regclass) NOT NULL,
    name character varying(100),
    description character varying(100),
    data_def jsonb,
    widget_def jsonb,
    option_def jsonb,
    type character varying(20),
    query_id bigint
);
 )   DROP TABLE leggero.lg_composite_widgets;
       leggero            postgres    false    254    5            �           0    0     COLUMN lg_composite_widgets.type    COMMENT     O   COMMENT ON COLUMN leggero.lg_composite_widgets.type IS 'individual/composite';
          leggero          postgres    false    255                        1259    313335    lg_dashboards_id_seq    SEQUENCE     ~   CREATE SEQUENCE leggero.lg_dashboards_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 ,   DROP SEQUENCE leggero.lg_dashboards_id_seq;
       leggero          admin    false    5                       1259    313337    lg_dashboards    TABLE     �  CREATE TABLE leggero.lg_dashboards (
    id bigint DEFAULT nextval('leggero.lg_dashboards_id_seq'::regclass) NOT NULL,
    name character varying(100),
    description character varying(200),
    dtitle character varying(255),
    row_def jsonb,
    db_file character varying(100) NOT NULL,
    dash_params jsonb,
    has_chart boolean DEFAULT false NOT NULL,
    has_report boolean DEFAULT false NOT NULL,
    has_widget boolean DEFAULT false NOT NULL,
    has_text boolean DEFAULT false NOT NULL
);
 "   DROP TABLE leggero.lg_dashboards;
       leggero            admin    false    256    5                       1259    313348    lg_department_id_seq    SEQUENCE     ~   CREATE SEQUENCE leggero.lg_department_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 ,   DROP SEQUENCE leggero.lg_department_id_seq;
       leggero          admin    false    5                       1259    313350    lg_department    TABLE     �   CREATE TABLE leggero.lg_department (
    id bigint DEFAULT nextval('leggero.lg_department_id_seq'::regclass) NOT NULL,
    dept_id character varying(40) NOT NULL,
    name character varying(50) NOT NULL
);
 "   DROP TABLE leggero.lg_department;
       leggero            admin    false    258    5                       1259    313354    lg_department_period    TABLE     �   CREATE TABLE leggero.lg_department_period (
    dept_id bigint NOT NULL,
    emp_id bigint NOT NULL,
    from_date date NOT NULL,
    to_date date NOT NULL
);
 )   DROP TABLE leggero.lg_department_period;
       leggero            admin    false    5                       1259    313357    lg_dshb_group_id_seq    SEQUENCE     ~   CREATE SEQUENCE leggero.lg_dshb_group_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 ,   DROP SEQUENCE leggero.lg_dshb_group_id_seq;
       leggero          admin    false    5                       1259    313359    lg_dshb_group    TABLE       CREATE TABLE leggero.lg_dshb_group (
    id bigint DEFAULT nextval('leggero.lg_dshb_group_id_seq'::regclass) NOT NULL,
    name character varying(100) NOT NULL,
    description character varying(200),
    display_name character varying(45),
    icon_class character varying(100)
);
 "   DROP TABLE leggero.lg_dshb_group;
       leggero            admin    false    261    5                       1259    313363    lg_dshb_group_user_id_seq    SEQUENCE     �   CREATE SEQUENCE leggero.lg_dshb_group_user_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 1   DROP SEQUENCE leggero.lg_dshb_group_user_id_seq;
       leggero          admin    false    5                       1259    313365    lg_dshb_group_user    TABLE     �   CREATE TABLE leggero.lg_dshb_group_user (
    id bigint DEFAULT nextval('leggero.lg_dshb_group_user_id_seq'::regclass) NOT NULL,
    user_id bigint NOT NULL,
    dshb_group_id bigint NOT NULL,
    status character varying(45),
    "order" bigint
);
 '   DROP TABLE leggero.lg_dshb_group_user;
       leggero            admin    false    263    5            	           1259    313369    lg_dshbgroup_dashboard_id_seq    SEQUENCE     �   CREATE SEQUENCE leggero.lg_dshbgroup_dashboard_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 5   DROP SEQUENCE leggero.lg_dshbgroup_dashboard_id_seq;
       leggero          admin    false    5            
           1259    313371    lg_dshbgroup_dashboard    TABLE       CREATE TABLE leggero.lg_dshbgroup_dashboard (
    id bigint DEFAULT nextval('leggero.lg_dshbgroup_dashboard_id_seq'::regclass) NOT NULL,
    dashboard_id bigint NOT NULL,
    dshbgroup_id bigint NOT NULL,
    status character varying(45),
    "order" bigint
);
 +   DROP TABLE leggero.lg_dshbgroup_dashboard;
       leggero            admin    false    265    5                       1259    313375    lg_employee_id_seq    SEQUENCE     |   CREATE SEQUENCE leggero.lg_employee_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 *   DROP SEQUENCE leggero.lg_employee_id_seq;
       leggero          admin    false    5                       1259    313377    lg_employee    TABLE     	  CREATE TABLE leggero.lg_employee (
    id bigint DEFAULT nextval('leggero.lg_employee_id_seq'::regclass) NOT NULL,
    emp_id character varying(40) NOT NULL,
    fname character varying(50),
    lname character varying(50),
    dob date,
    mobile1 character varying(20),
    email character varying(60),
    work character varying(50),
    designation character varying(50),
    jobrole character varying(50),
    hire_date date,
    parent_emp_id character varying(40),
    user_name character varying(40) NOT NULL
);
     DROP TABLE leggero.lg_employee;
       leggero            admin    false    267    5                       1259    313381    lg_grp_period    TABLE     �   CREATE TABLE leggero.lg_grp_period (
    grp_id bigint NOT NULL,
    user_id bigint NOT NULL,
    from_date date NOT NULL,
    to_date date NOT NULL
);
 "   DROP TABLE leggero.lg_grp_period;
       leggero            admin    false    5                       1259    313384    lg_jobstore    TABLE     �   CREATE TABLE leggero.lg_jobstore (
    id character varying(191) NOT NULL,
    next_run_time double precision,
    job_state bytea NOT NULL
);
     DROP TABLE leggero.lg_jobstore;
       leggero            admin    false    5                       1259    313390    lg_query_id_seq    SEQUENCE     y   CREATE SEQUENCE leggero.lg_query_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 '   DROP SEQUENCE leggero.lg_query_id_seq;
       leggero          admin    false    5                       1259    313392    lg_query    TABLE     d  CREATE TABLE leggero.lg_query (
    id bigint DEFAULT nextval('leggero.lg_query_id_seq'::regclass) NOT NULL,
    name character varying(100) NOT NULL,
    description text,
    ao_name character varying(45),
    tao_name character varying(45),
    vao_name character varying(45),
    group_cols text,
    filter_cols text,
    grp_filter text,
    qry_string text,
    param_val jsonb,
    dep_stat character varying(45) DEFAULT 'Active'::character varying,
    selected_cols jsonb,
    hidden_param_val jsonb,
    is_filter_query boolean DEFAULT false NOT NULL,
    is_multilevel_query boolean DEFAULT false
);
    DROP TABLE leggero.lg_query;
       leggero            admin    false    271    5                       1259    313402 "   lg_rep_dashboard_group_to_user_seq    SEQUENCE     �   CREATE SEQUENCE leggero.lg_rep_dashboard_group_to_user_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    MAXVALUE 2147483647
    CACHE 1;
 :   DROP SEQUENCE leggero.lg_rep_dashboard_group_to_user_seq;
       leggero          postgres    false    5                       1259    313404    lg_rep_dashboard_group_to_user    TABLE       CREATE TABLE leggero.lg_rep_dashboard_group_to_user (
    id bigint DEFAULT nextval('leggero.lg_rep_dashboard_group_to_user_seq'::regclass) NOT NULL,
    user_id bigint,
    rep_dashboard_group_id bigint,
    status character varying(45),
    "order" bigint
);
 3   DROP TABLE leggero.lg_rep_dashboard_group_to_user;
       leggero            postgres    false    273    5                       1259    313408 !   lg_rep_dashboard_to_dashgroup_seq    SEQUENCE     �   CREATE SEQUENCE leggero.lg_rep_dashboard_to_dashgroup_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    MAXVALUE 2147483647
    CACHE 1;
 9   DROP SEQUENCE leggero.lg_rep_dashboard_to_dashgroup_seq;
       leggero          postgres    false    5                       1259    313410    lg_rep_dashboard_to_dashgroup    TABLE       CREATE TABLE leggero.lg_rep_dashboard_to_dashgroup (
    id bigint DEFAULT nextval('leggero.lg_rep_dashboard_to_dashgroup_seq'::regclass) NOT NULL,
    rep_dashboard_id bigint,
    rep_dashgroup_id bigint,
    status character varying(45),
    "order" bigint
);
 2   DROP TABLE leggero.lg_rep_dashboard_to_dashgroup;
       leggero            postgres    false    275    5                       1259    313414    lg_report_group_id_seq    SEQUENCE     �   CREATE SEQUENCE leggero.lg_report_group_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 .   DROP SEQUENCE leggero.lg_report_group_id_seq;
       leggero          admin    false    5                       1259    313416    lg_report_group    TABLE     �   CREATE TABLE leggero.lg_report_group (
    id bigint DEFAULT nextval('leggero.lg_report_group_id_seq'::regclass) NOT NULL,
    name character varying(45),
    description character varying(200)
);
 $   DROP TABLE leggero.lg_report_group;
       leggero            admin    false    277    5                       1259    313420    lg_reports_id_seq    SEQUENCE     {   CREATE SEQUENCE leggero.lg_reports_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 )   DROP SEQUENCE leggero.lg_reports_id_seq;
       leggero          admin    false    5                       1259    313422 
   lg_reports    TABLE     "  CREATE TABLE leggero.lg_reports (
    id bigint DEFAULT nextval('leggero.lg_reports_id_seq'::regclass) NOT NULL,
    name character varying(45),
    description character varying(200),
    col_def jsonb,
    param_def jsonb,
    query_id bigint,
    is_multi_level boolean DEFAULT false
);
    DROP TABLE leggero.lg_reports;
       leggero            admin    false    279    5                       1259    313430    lg_rgroup_report_id_seq    SEQUENCE     �   CREATE SEQUENCE leggero.lg_rgroup_report_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 /   DROP SEQUENCE leggero.lg_rgroup_report_id_seq;
       leggero          admin    false    5                       1259    313432    lg_rgroup_report    TABLE     �   CREATE TABLE leggero.lg_rgroup_report (
    id bigint DEFAULT nextval('leggero.lg_rgroup_report_id_seq'::regclass) NOT NULL,
    report_id bigint NOT NULL,
    rgroup_id bigint NOT NULL,
    status character varying(45)
);
 %   DROP TABLE leggero.lg_rgroup_report;
       leggero            admin    false    281    5            J           1259    314207    lg_repgroup_rep    VIEW     �  CREATE VIEW leggero.lg_repgroup_rep AS
 SELECT concat(lg_report_group.id, NULLIF(lg_rgroup_report.id, 0), NULLIF(lg_reports.id, 0)) AS viewid,
    lg_report_group.id AS rgroupid,
    lg_report_group.name AS rgroupname,
    lg_report_group.description AS rgroupdesc,
    lg_rgroup_report.id AS rgrouprepid,
    lg_rgroup_report.status AS rgrouprepstatus,
    lg_reports.id AS repid,
    lg_reports.name AS repname,
    lg_reports.description AS repdesc,
    lg_reports.query_id
   FROM ((leggero.lg_report_group
     LEFT JOIN leggero.lg_rgroup_report ON ((lg_rgroup_report.rgroup_id = lg_report_group.id)))
     LEFT JOIN leggero.lg_reports ON ((lg_rgroup_report.report_id = lg_reports.id)));
 #   DROP VIEW leggero.lg_repgroup_rep;
       leggero          postgres    false    278    282    282    282    282    280    280    280    280    278    278    5                       1259    313441    lg_report_dashboard_seq    SEQUENCE     �   CREATE SEQUENCE leggero.lg_report_dashboard_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    MAXVALUE 2147483647
    CACHE 1;
 /   DROP SEQUENCE leggero.lg_report_dashboard_seq;
       leggero          postgres    false    5                       1259    313443    lg_report_dashboard    TABLE       CREATE TABLE leggero.lg_report_dashboard (
    id bigint DEFAULT nextval('leggero.lg_report_dashboard_seq'::regclass) NOT NULL,
    name character varying(100),
    rep_name character varying(255),
    rep_description character varying(255),
    row_def jsonb,
    dash_params jsonb
);
 (   DROP TABLE leggero.lg_report_dashboard;
       leggero            postgres    false    283    5                       1259    313450    lg_report_dashboard_group_seq    SEQUENCE     �   CREATE SEQUENCE leggero.lg_report_dashboard_group_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    MAXVALUE 2147483647
    CACHE 1;
 5   DROP SEQUENCE leggero.lg_report_dashboard_group_seq;
       leggero          postgres    false    5                       1259    313452    lg_report_dashboard_group    TABLE     4  CREATE TABLE leggero.lg_report_dashboard_group (
    id bigint DEFAULT nextval('leggero.lg_report_dashboard_group_seq'::regclass) NOT NULL,
    name character varying(100),
    rep_dashgroup_name character varying(100),
    rep_dashgroup_desc character varying(200),
    icon_class character varying(100)
);
 .   DROP TABLE leggero.lg_report_dashboard_group;
       leggero            postgres    false    285    5                       1259    313459    lg_rgroup_user_id_seq    SEQUENCE        CREATE SEQUENCE leggero.lg_rgroup_user_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 -   DROP SEQUENCE leggero.lg_rgroup_user_id_seq;
       leggero          admin    false    5                        1259    313461    lg_rgroup_user    TABLE     �   CREATE TABLE leggero.lg_rgroup_user (
    id bigint DEFAULT nextval('leggero.lg_rgroup_user_id_seq'::regclass) NOT NULL,
    user_id bigint NOT NULL,
    rgroup_id bigint NOT NULL,
    status character varying(45)
);
 #   DROP TABLE leggero.lg_rgroup_user;
       leggero            admin    false    287    5            !           1259    313465    lg_user_id_seq    SEQUENCE     x   CREATE SEQUENCE leggero.lg_user_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 &   DROP SEQUENCE leggero.lg_user_id_seq;
       leggero          admin    false    5            "           1259    313467    lg_user    TABLE     '  CREATE TABLE leggero.lg_user (
    id bigint DEFAULT nextval('leggero.lg_user_id_seq'::regclass) NOT NULL,
    user_name character varying(40) NOT NULL,
    is_active character varying(2) NOT NULL,
    is_system character varying(2),
    is_admin character varying(2) NOT NULL,
    pwd bytea
);
    DROP TABLE leggero.lg_user;
       leggero            admin    false    289    5            =           1259    314147    lg_show_dash_group    VIEW     �  CREATE VIEW leggero.lg_show_dash_group AS
 SELECT concat(b.dshb_group_id, a.user_name, c.id) AS viewid,
    a.user_name AS username,
    b.dshb_group_id AS dashboard_group_id,
    c.name,
    c.display_name,
    b."order"
   FROM ((leggero.lg_user a
     LEFT JOIN leggero.lg_dshb_group_user b ON ((a.id = b.user_id)))
     LEFT JOIN leggero.lg_dshb_group c ON ((b.dshb_group_id = c.id)))
  WHERE ((b.status)::text = 'Active'::text);
 &   DROP VIEW leggero.lg_show_dash_group;
       leggero          postgres    false    290    290    264    264    264    264    262    262    262    5            ;           1259    314137    lg_show_dashboard    VIEW     �  CREATE VIEW leggero.lg_show_dashboard AS
 SELECT concat(b.dshb_group_id, a.user_name, c.dashboard_id) AS viewid,
    a.user_name AS username,
    b.dshb_group_id AS dashboard_group_id,
    c.dashboard_id,
    c."order",
    d.name AS dashboard_name,
    d.dtitle AS dashboard_title,
    d.db_file AS dashboard_file_name
   FROM (((leggero.lg_user a
     LEFT JOIN leggero.lg_dshb_group_user b ON ((a.id = b.user_id)))
     LEFT JOIN leggero.lg_dshbgroup_dashboard c ON ((b.dshb_group_id = c.dshbgroup_id)))
     LEFT JOIN leggero.lg_dashboards d ON ((c.dashboard_id = d.id)))
  WHERE (((b.status)::text = 'Active'::text) AND ((c.status)::text = 'Active'::text));
 %   DROP VIEW leggero.lg_show_dashboard;
       leggero          postgres    false    257    290    290    266    266    266    266    264    264    264    257    257    257    5            >           1259    314152    lg_show_dashboard_dashgroups    VIEW     �  CREATE VIEW leggero.lg_show_dashboard_dashgroups AS
 SELECT concat(b.dshb_group_id, a.user_name, c.dashboard_id, e.id) AS viewid,
    a.user_name AS username,
    b.dshb_group_id AS dashboard_group_id,
    c.dashboard_id,
    c."order",
    d.name AS dashboard_name,
    d.dtitle AS dashboard_title,
    d.db_file AS dashboard_file_name,
    e.name AS dashgroup_name,
    e.description AS dashgroup_description,
    e.display_name AS dashgroup_display_name
   FROM ((((leggero.lg_user a
     LEFT JOIN leggero.lg_dshb_group_user b ON ((a.id = b.user_id)))
     LEFT JOIN leggero.lg_dshbgroup_dashboard c ON ((b.dshb_group_id = c.dshbgroup_id)))
     LEFT JOIN leggero.lg_dashboards d ON ((c.dashboard_id = d.id)))
     LEFT JOIN leggero.lg_dshb_group e ON ((e.id = c.dshbgroup_id)))
  WHERE (((b.status)::text = 'Active'::text) AND ((c.status)::text = 'Active'::text) AND (d.has_report = false));
 0   DROP VIEW leggero.lg_show_dashboard_dashgroups;
       leggero          postgres    false    257    257    257    257    257    262    262    262    262    264    264    264    266    266    266    266    290    290    5            G           1259    314192    lg_show_report_dashboard    VIEW     �  CREATE VIEW leggero.lg_show_report_dashboard AS
 SELECT concat(a.id, b.rep_dashboard_group_id, c.rep_dashboard_id) AS view_id,
    a.id AS user_id,
    a.user_name,
    b.rep_dashboard_group_id,
    c.rep_dashboard_id,
    c.status AS dashboard_status,
    c."order" AS dashboard_order,
    d.rep_name,
    d.rep_description,
    d.row_def,
    d.dash_params
   FROM (((leggero.lg_user a
     LEFT JOIN leggero.lg_rep_dashboard_group_to_user b ON ((a.id = b.user_id)))
     LEFT JOIN leggero.lg_rep_dashboard_to_dashgroup c ON ((b.rep_dashboard_group_id = c.rep_dashgroup_id)))
     LEFT JOIN leggero.lg_report_dashboard d ON ((c.rep_dashboard_id = d.id)))
  WHERE (((b.status)::text = 'Active'::text) AND ((c.status)::text = 'Active'::text));
 ,   DROP VIEW leggero.lg_show_report_dashboard;
       leggero          postgres    false    276    276    276    276    284    284    290    290    284    284    284    274    274    274    5            :           1259    314132 "   lg_show_report_dashboard_dashgroup    VIEW     �  CREATE VIEW leggero.lg_show_report_dashboard_dashgroup AS
 SELECT concat(a.id, b.dshb_group_id, c.dashboard_id, e.id) AS view_id,
    a.id AS user_id,
    a.user_name,
    c.dshbgroup_id AS dashboard_group_id,
    c.dashboard_id,
    c.status AS dashboard_status,
    c."order",
    d.name AS dashboard_name,
    d.description AS dashboard_description,
    d.row_def,
    d.dash_params,
    e.name AS dashgroup_name,
    e.display_name AS dashgroup_display_name,
    e.description AS dashgroup_description
   FROM ((((leggero.lg_user a
     LEFT JOIN leggero.lg_dshb_group_user b ON ((a.id = b.user_id)))
     LEFT JOIN leggero.lg_dshbgroup_dashboard c ON ((b.dshb_group_id = c.dshbgroup_id)))
     LEFT JOIN leggero.lg_dashboards d ON ((c.dashboard_id = d.id)))
     LEFT JOIN leggero.lg_dshb_group e ON ((e.id = c.dshbgroup_id)))
  WHERE (((b.status)::text = 'Active'::text) AND ((c.status)::text = 'Active'::text) AND (d.has_report = true));
 6   DROP VIEW leggero.lg_show_report_dashboard_dashgroup;
       leggero          postgres    false    264    264    262    262    262    266    264    266    266    257    257    257    257    257    262    266    290    290    257    5            H           1259    314197    lg_show_report_dashboard_group    VIEW        CREATE VIEW leggero.lg_show_report_dashboard_group AS
 SELECT concat(b.user_id, b.rep_dashboard_group_id) AS view_id,
    b.user_id,
    b.rep_dashboard_group_id,
    a.user_name,
    c.rep_dashgroup_name,
    c.rep_dashgroup_desc,
    c.icon_class,
    b.status,
    b."order"
   FROM ((leggero.lg_user a
     LEFT JOIN leggero.lg_rep_dashboard_group_to_user b ON ((a.id = b.user_id)))
     LEFT JOIN leggero.lg_report_dashboard_group c ON ((b.rep_dashboard_group_id = c.id)))
  WHERE ((b.status)::text = 'Active'::text)
  ORDER BY b."order";
 2   DROP VIEW leggero.lg_show_report_dashboard_group;
       leggero          postgres    false    274    274    290    290    286    286    286    286    274    274    5            <           1259    314142    lg_show_reps    VIEW     �  CREATE VIEW leggero.lg_show_reps AS
 SELECT DISTINCT lg_user_reps.repid AS id,
    lg_user_reps.repname AS name,
    lg_user_reps.repdesc AS description,
    lg_user_reps.col_def,
    lg_user_reps.query_id,
    lg_user_reps.username,
    concat(lg_user_reps.repid, lg_user_reps.username) AS viewid
   FROM ( SELECT lg_reports.name AS repname,
            lg_reports.description AS repdesc,
            lg_reports.col_def,
            lg_reports.query_id,
            lg_reports.id AS repid,
            lg_rgroup_user.status AS rgroupuserstatus,
            lg_rgroup_report.status AS rgrouprepstatus,
            lg_user.user_name AS username
           FROM ((((leggero.lg_user
             LEFT JOIN leggero.lg_rgroup_user ON ((lg_user.id = lg_rgroup_user.user_id)))
             LEFT JOIN leggero.lg_report_group ON ((lg_report_group.id = lg_rgroup_user.rgroup_id)))
             LEFT JOIN leggero.lg_rgroup_report ON ((lg_rgroup_report.rgroup_id = lg_report_group.id)))
             LEFT JOIN leggero.lg_reports ON ((lg_rgroup_report.report_id = lg_reports.id)))) lg_user_reps
  WHERE (((lg_user_reps.rgroupuserstatus)::text = 'Active'::text) AND ((lg_user_reps.rgrouprepstatus)::text = 'Active'::text));
     DROP VIEW leggero.lg_show_reps;
       leggero          postgres    false    278    280    280    280    280    280    282    282    282    288    288    288    290    290    5            #           1259    313509    lg_user_home_dashboard_seq    SEQUENCE     �   CREATE SEQUENCE leggero.lg_user_home_dashboard_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    MAXVALUE 2147483647
    CACHE 1;
 2   DROP SEQUENCE leggero.lg_user_home_dashboard_seq;
       leggero          postgres    false    5            $           1259    313511    lg_user_home_dashboard    TABLE     �   CREATE TABLE leggero.lg_user_home_dashboard (
    id bigint DEFAULT nextval('leggero.lg_user_home_dashboard_seq'::regclass) NOT NULL,
    user_id bigint NOT NULL,
    dashboard_id bigint NOT NULL,
    status character varying(45) NOT NULL
);
 +   DROP TABLE leggero.lg_user_home_dashboard;
       leggero            postgres    false    291    5            D           1259    314178    lg_show_user_home_dashboard    VIEW     v  CREATE VIEW leggero.lg_show_user_home_dashboard AS
 SELECT concat(a.user_id, a.dashboard_id) AS view_id,
    a.id,
    a.user_id,
    a.dashboard_id,
    b.user_name,
    c.dtitle,
    c.description,
    a.status
   FROM ((leggero.lg_user_home_dashboard a
     JOIN leggero.lg_user b ON ((a.user_id = b.id)))
     JOIN leggero.lg_dashboards c ON ((a.dashboard_id = c.id)));
 /   DROP VIEW leggero.lg_show_user_home_dashboard;
       leggero          postgres    false    257    257    257    290    290    292    292    292    292    5            %           1259    313520    lg_tables_id_seq    SEQUENCE     z   CREATE SEQUENCE leggero.lg_tables_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 (   DROP SEQUENCE leggero.lg_tables_id_seq;
       leggero          admin    false    5            &           1259    313522 	   lg_tables    TABLE     �   CREATE TABLE leggero.lg_tables (
    id bigint DEFAULT nextval('leggero.lg_tables_id_seq'::regclass) NOT NULL,
    name character varying(200) NOT NULL,
    data_source_id bigint NOT NULL,
    dep_stat character varying(45)
);
    DROP TABLE leggero.lg_tables;
       leggero            admin    false    293    5            '           1259    313526    lg_user_grp_id_seq    SEQUENCE     |   CREATE SEQUENCE leggero.lg_user_grp_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 *   DROP SEQUENCE leggero.lg_user_grp_id_seq;
       leggero          admin    false    5            (           1259    313528    lg_user_grp    TABLE     �   CREATE TABLE leggero.lg_user_grp (
    id bigint DEFAULT nextval('leggero.lg_user_grp_id_seq'::regclass) NOT NULL,
    grp_id character varying(40) NOT NULL,
    name character varying(50) NOT NULL
);
     DROP TABLE leggero.lg_user_grp;
       leggero            admin    false    295    5            I           1259    314202    lg_user_repgroup    VIEW     b  CREATE VIEW leggero.lg_user_repgroup AS
 SELECT concat(lg_user.id, NULLIF(lg_rgroup_user.id, 0), NULLIF(lg_report_group.id, 0)) AS viewid,
    lg_user.id AS userid,
    lg_user.user_name AS username,
    lg_rgroup_user.id AS rgroupuserid,
    lg_rgroup_user.status AS rgroupuserstatus,
    lg_report_group.id AS rgroupid,
    lg_report_group.name AS rgroupname,
    lg_report_group.description AS rgroupdesc
   FROM ((leggero.lg_user
     LEFT JOIN leggero.lg_rgroup_user ON ((lg_user.id = lg_rgroup_user.user_id)))
     LEFT JOIN leggero.lg_report_group ON ((lg_report_group.id = lg_rgroup_user.rgroup_id)));
 $   DROP VIEW leggero.lg_user_repgroup;
       leggero          postgres    false    290    288    288    288    288    278    278    278    290    5            F           1259    314187    lg_user_reps    VIEW     (  CREATE VIEW leggero.lg_user_reps AS
 SELECT concat(lg_user.user_name, NULLIF((lg_report_group.name)::text, '-'::text), NULLIF((lg_reports.name)::text, '-'::text)) AS viewid,
    lg_user.id AS userid,
    lg_user.user_name AS username,
    lg_rgroup_user.id AS rgroupuserid,
    lg_rgroup_user.status AS rgroupuserstatus,
    lg_report_group.id AS rgroupid,
    lg_report_group.name AS rgroupname,
    lg_report_group.description AS rgroupdesc,
    lg_rgroup_report.id AS rgrouprepid,
    lg_rgroup_report.status AS rgrouprepstatus,
    lg_reports.id AS repid,
    lg_reports.name AS repname,
    lg_reports.description AS repdesc,
    lg_reports.col_def,
    lg_reports.query_id
   FROM ((((leggero.lg_user
     LEFT JOIN leggero.lg_rgroup_user ON ((lg_user.id = lg_rgroup_user.user_id)))
     LEFT JOIN leggero.lg_report_group ON ((lg_report_group.id = lg_rgroup_user.rgroup_id)))
     LEFT JOIN leggero.lg_rgroup_report ON ((lg_rgroup_report.rgroup_id = lg_report_group.id)))
     LEFT JOIN leggero.lg_reports ON ((lg_rgroup_report.report_id = lg_reports.id)));
     DROP VIEW leggero.lg_user_reps;
       leggero          postgres    false    288    278    278    278    280    280    280    280    280    282    282    282    282    288    288    288    290    290    5            B           1259    314170    lg_user_wo_pass    VIEW     u   CREATE VIEW leggero.lg_user_wo_pass AS
 SELECT lg_user.id AS user_id,
    lg_user.user_name
   FROM leggero.lg_user;
 #   DROP VIEW leggero.lg_user_wo_pass;
       leggero          postgres    false    290    290    5            )           1259    313546    lg_view_cols_id_seq    SEQUENCE     }   CREATE SEQUENCE leggero.lg_view_cols_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 +   DROP SEQUENCE leggero.lg_view_cols_id_seq;
       leggero          admin    false    5            *           1259    313548    lg_view_cols    TABLE     ?  CREATE TABLE leggero.lg_view_cols (
    id bigint DEFAULT nextval('leggero.lg_view_cols_id_seq'::regclass) NOT NULL,
    name character varying(45) NOT NULL,
    ds_name character varying(45) NOT NULL,
    name_in_ds character varying(45) NOT NULL,
    cast_type character varying(45),
    parent_id bigint NOT NULL
);
 !   DROP TABLE leggero.lg_view_cols;
       leggero            admin    false    297    5            +           1259    313552    lg_view_tables_id_seq    SEQUENCE        CREATE SEQUENCE leggero.lg_view_tables_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 -   DROP SEQUENCE leggero.lg_view_tables_id_seq;
       leggero          admin    false    5            ,           1259    313554    lg_view_tables    TABLE     V  CREATE TABLE leggero.lg_view_tables (
    id bigint DEFAULT nextval('leggero.lg_view_tables_id_seq'::regclass) NOT NULL,
    join_ds1 character varying(45) NOT NULL,
    join_column1 character varying(45) NOT NULL,
    join_ds2 character varying(45) NOT NULL,
    join_column2 character varying(45) NOT NULL,
    parent_id bigint NOT NULL
);
 #   DROP TABLE leggero.lg_view_tables;
       leggero            admin    false    299    5            -           1259    313558    lg_views_id_seq    SEQUENCE     y   CREATE SEQUENCE leggero.lg_views_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 '   DROP SEQUENCE leggero.lg_views_id_seq;
       leggero          admin    false    5            .           1259    313560    lg_views    TABLE     �   CREATE TABLE leggero.lg_views (
    id bigint DEFAULT nextval('leggero.lg_views_id_seq'::regclass) NOT NULL,
    name character varying(45) NOT NULL,
    recfilter character varying(100),
    dep_stat character varying(45)
);
    DROP TABLE leggero.lg_views;
       leggero            admin    false    301    5            /           1259    313564    lg_vinsights_id_seq    SEQUENCE     }   CREATE SEQUENCE leggero.lg_vinsights_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 +   DROP SEQUENCE leggero.lg_vinsights_id_seq;
       leggero          admin    false    5            0           1259    313566    lg_vinsights    TABLE     a  CREATE TABLE leggero.lg_vinsights (
    id bigint DEFAULT nextval('leggero.lg_vinsights_id_seq'::regclass) NOT NULL,
    name character varying(100),
    description character varying(200),
    vi_type character varying(200),
    option_def jsonb,
    query_id bigint,
    data_def jsonb,
    child_id bigint DEFAULT '0'::bigint,
    email_def jsonb
);
 !   DROP TABLE leggero.lg_vinsights;
       leggero            admin    false    303    5            1           1259    313574    report_configurations    TABLE       CREATE TABLE leggero.report_configurations (
    id integer NOT NULL,
    report_configurations2version integer,
    write_configuration jsonb,
    status smallint DEFAULT 1,
    tablename character varying,
    report_configuration_name character varying
);
 *   DROP TABLE leggero.report_configurations;
       leggero            postgres    false    5            2           1259    313581    report_configurations_id_seq    SEQUENCE     �   CREATE SEQUENCE leggero.report_configurations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 4   DROP SEQUENCE leggero.report_configurations_id_seq;
       leggero          postgres    false    5    305            �           0    0    report_configurations_id_seq    SEQUENCE OWNED BY     _   ALTER SEQUENCE leggero.report_configurations_id_seq OWNED BY leggero.report_configurations.id;
          leggero          postgres    false    306            3           1259    313583    run_schedule_rules    TABLE     �  CREATE TABLE leggero.run_schedule_rules (
    id integer NOT NULL,
    rule_name character varying NOT NULL,
    rule_id character varying,
    status character varying(20) NOT NULL,
    rule_description text,
    rule_json jsonb NOT NULL,
    create_datetime timestamp without time zone NOT NULL,
    lastchange_datetime timestamp without time zone NOT NULL,
    schedule2pipeline integer
);
 '   DROP TABLE leggero.run_schedule_rules;
       leggero            postgres    false    5            4           1259    313589    run_schedule_rules_id_seq    SEQUENCE     �   ALTER TABLE leggero.run_schedule_rules ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME leggero.run_schedule_rules_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);
            leggero          postgres    false    307    5            5           1259    313591    schedule_instance    TABLE     T  CREATE TABLE leggero.schedule_instance (
    id integer NOT NULL,
    instance2schedule integer NOT NULL,
    create_datetime timestamp without time zone NOT NULL,
    lastchange_datetime timestamp without time zone NOT NULL,
    prev_rundate date,
    prev_runtime time without time zone,
    schedule_ins2pipeline_ins integer NOT NULL
);
 &   DROP TABLE leggero.schedule_instance;
       leggero            postgres    false    5            6           1259    313594    schedule_instance_id_seq    SEQUENCE     �   ALTER TABLE leggero.schedule_instance ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME leggero.schedule_instance_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);
            leggero          postgres    false    309    5            7           1259    313596    write_to_db_configuration    TABLE       CREATE TABLE leggero.write_to_db_configuration (
    id integer NOT NULL,
    write_db_config2version integer,
    tablename character varying,
    status boolean,
    decision_filter_config_fe jsonb,
    decision_filter_config_be jsonb,
    column_config jsonb,
    db_meta_config jsonb,
    output_column_config jsonb,
    create_datetime timestamp without time zone,
    lastchange_datetime timestamp without time zone,
    con_string_name character varying NOT NULL,
    configuration_name character varying
);
 .   DROP TABLE leggero.write_to_db_configuration;
       leggero            postgres    false    5            8           1259    313602     write_to_db_configuration_id_seq    SEQUENCE     �   CREATE SEQUENCE leggero.write_to_db_configuration_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 8   DROP SEQUENCE leggero.write_to_db_configuration_id_seq;
       leggero          postgres    false    311    5            �           0    0     write_to_db_configuration_id_seq    SEQUENCE OWNED BY     g   ALTER SEQUENCE leggero.write_to_db_configuration_id_seq OWNED BY leggero.write_to_db_configuration.id;
          leggero          postgres    false    312            �           2604    313604    api_definition id    DEFAULT     x   ALTER TABLE ONLY leggero.api_definition ALTER COLUMN id SET DEFAULT nextval('leggero.api_definition_id_seq'::regclass);
 A   ALTER TABLE leggero.api_definition ALTER COLUMN id DROP DEFAULT;
       leggero          postgres    false    201    200            �           2604    313605    dds_api_writer id    DEFAULT     x   ALTER TABLE ONLY leggero.dds_api_writer ALTER COLUMN id SET DEFAULT nextval('leggero.dds_api_writer_id_seq'::regclass);
 A   ALTER TABLE leggero.dds_api_writer ALTER COLUMN id DROP DEFAULT;
       leggero          postgres    false    213    212            �           2604    313606    dds_filter_functions id    DEFAULT     �   ALTER TABLE ONLY leggero.dds_filter_functions ALTER COLUMN id SET DEFAULT nextval('leggero.dds_filter_functions_id_seq'::regclass);
 G   ALTER TABLE leggero.dds_filter_functions ALTER COLUMN id DROP DEFAULT;
       leggero          admin    false    217    216            �           2604    313607    dds_global_imports id    DEFAULT     �   ALTER TABLE ONLY leggero.dds_global_imports ALTER COLUMN id SET DEFAULT nextval('leggero.dds_global_imports_id_seq'::regclass);
 E   ALTER TABLE leggero.dds_global_imports ALTER COLUMN id DROP DEFAULT;
       leggero          admin    false    221    220            �           2604    313608    dds_mapping id    DEFAULT     r   ALTER TABLE ONLY leggero.dds_mapping ALTER COLUMN id SET DEFAULT nextval('leggero.dds_mapping_id_seq'::regclass);
 >   ALTER TABLE leggero.dds_mapping ALTER COLUMN id DROP DEFAULT;
       leggero          postgres    false    223    222                       2604    313609    report_configurations id    DEFAULT     �   ALTER TABLE ONLY leggero.report_configurations ALTER COLUMN id SET DEFAULT nextval('leggero.report_configurations_id_seq'::regclass);
 H   ALTER TABLE leggero.report_configurations ALTER COLUMN id DROP DEFAULT;
       leggero          postgres    false    306    305                       2604    313610    write_to_db_configuration id    DEFAULT     �   ALTER TABLE ONLY leggero.write_to_db_configuration ALTER COLUMN id SET DEFAULT nextval('leggero.write_to_db_configuration_id_seq'::regclass);
 L   ALTER TABLE leggero.write_to_db_configuration ALTER COLUMN id DROP DEFAULT;
       leggero          postgres    false    312    311            s          0    313080    Communication_Templates 
   TABLE DATA           k   COPY leggero."Communication_Templates" (id, name, description, data, status, type, has_params) FROM stdin;
    leggero          postgres    false    198   �h      u          0    313088    api_definition 
   TABLE DATA           �   COPY leggero.api_definition (id, api_name, api_type, input_json, output_json, status, api_definition2project, create_datetime, lastchange_datetime, input_json_map, output_json_map, api2auth_id, authentication_json, api_configuration_json) FROM stdin;
    leggero          postgres    false    200   �h      w          0    313096    api_writer_audit 
   TABLE DATA           �   COPY leggero.api_writer_audit (id, api_writer_audit2node_instance, input_json, output_json, api_writer_audit2pipe_ins, create_datetime, api_writer_audit2api_writer, record_pointer) FROM stdin;
    leggero          postgres    false    202   i      y          0    313104    at_email_configuration 
   TABLE DATA           �   COPY leggero.at_email_configuration (id, at2parent_object, app_username, db_username, insert_date, insert_time, changes, change_type) FROM stdin;
    leggero          postgres    false    204   %i      |          0    313114    connections 
   TABLE DATA           J   COPY leggero.connections (con_id, name, con_string, con_type) FROM stdin;
    leggero          admin    false    207   Bi      ~          0    313120 
   datasource 
   TABLE DATA           �   COPY leggero.datasource (ds_id, name, ds_table, ftype, connection_id, partition_col, lowerbound, upperbound, numpartitions, predicates, splitscheme, col_list, dep_stat) FROM stdin;
    leggero          admin    false    209   _i                0    313127    db_writer_audit 
   TABLE DATA           �   COPY leggero.db_writer_audit (id, db_writer_audit2node_instance, input_json, output_json, create_datetime, db_writer_audit2pipe_ins, db_writer_audit2db_writer, record_pointer) FROM stdin;
    leggero          postgres    false    210   |i      �          0    313135    dds_api_writer 
   TABLE DATA           �   COPY leggero.dds_api_writer (id, tablename, api_writer2version, api_writer2api_id, input_json_map, api_writer_name, status, create_datetime, lastchange_datetime) FROM stdin;
    leggero          postgres    false    212   �i      �          0    313143    dds_custom_functions 
   TABLE DATA           �   COPY leggero.dds_custom_functions (id, function_name, function_string, function_arguments, function_info, function2version, status) FROM stdin;
    leggero          admin    false    214   �i      �          0    313151    dds_filter_functions 
   TABLE DATA           �   COPY leggero.dds_filter_functions (id, function_name, function_string, function_info, function2version, status, tablename) FROM stdin;
    leggero          admin    false    216   j      �          0    313159    dds_ftp_definition 
   TABLE DATA           �   COPY leggero.dds_ftp_definition (id, host, username, password, create_datetime, lastchange_datetime, ftp_def2project, name, root_dir, status) FROM stdin;
    leggero          postgres    false    218   7j      �          0    313167    dds_global_imports 
   TABLE DATA           z   COPY leggero.dds_global_imports (id, function_name, function_string, function_info, function2version, status) FROM stdin;
    leggero          admin    false    220   Tj      �          0    313175    dds_mapping 
   TABLE DATA           l   COPY leggero.dds_mapping (id, mapping2dds_version, mapping_name, mapping_configuration, status) FROM stdin;
    leggero          postgres    false    222   qj      �          0    313185    dds_pipe_ins_log 
   TABLE DATA           {  COPY leggero.dds_pipe_ins_log (node_name, start_time, end_time, input_json, output_json, pipe_ins_log2pipe_instance, completion_status, error_status, error_json, id, activity_type, activity2report_config, activity2api_writer, activity2api_definition, activity2write_db, activity2version, node_type, runtime_metadata, node_label, create_datetime, lastchange_datetime) FROM stdin;
    leggero          postgres    false    225   �l      �          0    313198    dds_pipeline 
   TABLE DATA           t   COPY leggero.dds_pipeline (name, data_json, id, pipeline2version, create_datetime, lastchange_datetime) FROM stdin;
    leggero          postgres    false    227   �l      �          0    313207    dds_pipeline_activity_defs 
   TABLE DATA           �   COPY leggero.dds_pipeline_activity_defs (id, api_name, api_url, status, api_description, output_json_proto, activity_display_meta, activity_front_check_name, input_json_frontend) FROM stdin;
    leggero          postgres    false    229   �l      �          0    313222    dds_pipeline_instance 
   TABLE DATA           �   COPY leggero.dds_pipeline_instance (pipeline_instance2pipeline, name, start_time, end_time, instance_json, id, times_trigger_run, create_datetime, lastchange_datetime) FROM stdin;
    leggero          postgres    false    232   �x      �          0    313235    dds_project_versions 
   TABLE DATA           �   COPY leggero.dds_project_versions (id, version2project, name, description, version2parent_version, version_settings) FROM stdin;
    leggero          admin    false    234   �x      �          0    313241    dds_projects 
   TABLE DATA           P   COPY leggero.dds_projects (id, name, description, project_settings) FROM stdin;
    leggero          admin    false    235   �y      �          0    313260 
   dds_schema 
   TABLE DATA           Z   COPY leggero.dds_schema (id, schema, update_datetime, schema2project_version) FROM stdin;
    leggero          admin    false    238   |z      �          0    313268    dds_script_definition 
   TABLE DATA           �   COPY leggero.dds_script_definition (id, name, executor_path_id, script_path, input_args, output_json, active, script2project, create_datetime, lastchange_datetime, category, script_code) FROM stdin;
    leggero          postgres    false    240   ��      �          0    313276    dds_script_definition_instance 
   TABLE DATA           �   COPY leggero.dds_script_definition_instance (id, input_args, output_json, start_datetime, end_datetime, process_id, run_by, script2master, status, error_traceback) FROM stdin;
    leggero          postgres    false    242   ��      �          0    313284    dds_script_executors 
   TABLE DATA           G   COPY leggero.dds_script_executors (id, name, path, active) FROM stdin;
    leggero          postgres    false    244   ܱ      �          0    313296    email_configuration 
   TABLE DATA           �   COPY leggero.email_configuration (id, email_id, email_type, server_type, host, port, status, create_datetime, lastchange_datetime, password, description, name, polling_on, poll_frequency, app_username, email_configuration2project) FROM stdin;
    leggero          postgres    false    246   ��      �          0    313304    email_read_param_config 
   TABLE DATA           �   COPY leggero.email_read_param_config (id, name, create_datetime, lastchange_datetime, status, description, config_json, email_read_conf2email_config) FROM stdin;
    leggero          postgres    false    248   �      �          0    313314    lg_aofrmqry 
   TABLE DATA           D   COPY leggero.lg_aofrmqry (id, name, dep_stat, query_id) FROM stdin;
    leggero          admin    false    251   3�      �          0    313320 
   lg_columns 
   TABLE DATA           t   COPY leggero.lg_columns (id, name, name_in_ds, filter_use, cast_type, decimals, parent_id, parent_type) FROM stdin;
    leggero          admin    false    253   P�      �          0    313328    lg_composite_widgets 
   TABLE DATA           x   COPY leggero.lg_composite_widgets (id, name, description, data_def, widget_def, option_def, type, query_id) FROM stdin;
    leggero          postgres    false    255   m�      �          0    313337    lg_dashboards 
   TABLE DATA           �   COPY leggero.lg_dashboards (id, name, description, dtitle, row_def, db_file, dash_params, has_chart, has_report, has_widget, has_text) FROM stdin;
    leggero          admin    false    257   ��      �          0    313350    lg_department 
   TABLE DATA           ;   COPY leggero.lg_department (id, dept_id, name) FROM stdin;
    leggero          admin    false    259   -�      �          0    313354    lg_department_period 
   TABLE DATA           T   COPY leggero.lg_department_period (dept_id, emp_id, from_date, to_date) FROM stdin;
    leggero          admin    false    260   J�      �          0    313359    lg_dshb_group 
   TABLE DATA           Y   COPY leggero.lg_dshb_group (id, name, description, display_name, icon_class) FROM stdin;
    leggero          admin    false    262   g�      �          0    313365    lg_dshb_group_user 
   TABLE DATA           Z   COPY leggero.lg_dshb_group_user (id, user_id, dshb_group_id, status, "order") FROM stdin;
    leggero          admin    false    264   ��      �          0    313371    lg_dshbgroup_dashboard 
   TABLE DATA           b   COPY leggero.lg_dshbgroup_dashboard (id, dashboard_id, dshbgroup_id, status, "order") FROM stdin;
    leggero          admin    false    266   ��      �          0    313377    lg_employee 
   TABLE DATA           �   COPY leggero.lg_employee (id, emp_id, fname, lname, dob, mobile1, email, work, designation, jobrole, hire_date, parent_emp_id, user_name) FROM stdin;
    leggero          admin    false    268   ��      �          0    313381    lg_grp_period 
   TABLE DATA           M   COPY leggero.lg_grp_period (grp_id, user_id, from_date, to_date) FROM stdin;
    leggero          admin    false    269   ��      �          0    313384    lg_jobstore 
   TABLE DATA           D   COPY leggero.lg_jobstore (id, next_run_time, job_state) FROM stdin;
    leggero          admin    false    270   ��      �          0    313392    lg_query 
   TABLE DATA           �   COPY leggero.lg_query (id, name, description, ao_name, tao_name, vao_name, group_cols, filter_cols, grp_filter, qry_string, param_val, dep_stat, selected_cols, hidden_param_val, is_filter_query, is_multilevel_query) FROM stdin;
    leggero          admin    false    272   ��      �          0    313404    lg_rep_dashboard_group_to_user 
   TABLE DATA           o   COPY leggero.lg_rep_dashboard_group_to_user (id, user_id, rep_dashboard_group_id, status, "order") FROM stdin;
    leggero          postgres    false    274   �*      �          0    313410    lg_rep_dashboard_to_dashgroup 
   TABLE DATA           q   COPY leggero.lg_rep_dashboard_to_dashgroup (id, rep_dashboard_id, rep_dashgroup_id, status, "order") FROM stdin;
    leggero          postgres    false    276   q+      �          0    313443    lg_report_dashboard 
   TABLE DATA           i   COPY leggero.lg_report_dashboard (id, name, rep_name, rep_description, row_def, dash_params) FROM stdin;
    leggero          postgres    false    284   �+      �          0    313452    lg_report_dashboard_group 
   TABLE DATA           r   COPY leggero.lg_report_dashboard_group (id, name, rep_dashgroup_name, rep_dashgroup_desc, icon_class) FROM stdin;
    leggero          postgres    false    286   �,      �          0    313416    lg_report_group 
   TABLE DATA           A   COPY leggero.lg_report_group (id, name, description) FROM stdin;
    leggero          admin    false    278   .-      �          0    313422 
   lg_reports 
   TABLE DATA           j   COPY leggero.lg_reports (id, name, description, col_def, param_def, query_id, is_multi_level) FROM stdin;
    leggero          admin    false    280   K-      �          0    313432    lg_rgroup_report 
   TABLE DATA           M   COPY leggero.lg_rgroup_report (id, report_id, rgroup_id, status) FROM stdin;
    leggero          admin    false    282   �8      �          0    313461    lg_rgroup_user 
   TABLE DATA           I   COPY leggero.lg_rgroup_user (id, user_id, rgroup_id, status) FROM stdin;
    leggero          admin    false    288   �8      �          0    313522 	   lg_tables 
   TABLE DATA           H   COPY leggero.lg_tables (id, name, data_source_id, dep_stat) FROM stdin;
    leggero          admin    false    294   �8      �          0    313467    lg_user 
   TABLE DATA           V   COPY leggero.lg_user (id, user_name, is_active, is_system, is_admin, pwd) FROM stdin;
    leggero          admin    false    290   �8      �          0    313528    lg_user_grp 
   TABLE DATA           8   COPY leggero.lg_user_grp (id, grp_id, name) FROM stdin;
    leggero          admin    false    296   @      �          0    313511    lg_user_home_dashboard 
   TABLE DATA           T   COPY leggero.lg_user_home_dashboard (id, user_id, dashboard_id, status) FROM stdin;
    leggero          postgres    false    292   .@      �          0    313548    lg_view_cols 
   TABLE DATA           \   COPY leggero.lg_view_cols (id, name, ds_name, name_in_ds, cast_type, parent_id) FROM stdin;
    leggero          admin    false    298   �@      �          0    313554    lg_view_tables 
   TABLE DATA           h   COPY leggero.lg_view_tables (id, join_ds1, join_column1, join_ds2, join_column2, parent_id) FROM stdin;
    leggero          admin    false    300   �@      �          0    313560    lg_views 
   TABLE DATA           B   COPY leggero.lg_views (id, name, recfilter, dep_stat) FROM stdin;
    leggero          admin    false    302   �@      �          0    313566    lg_vinsights 
   TABLE DATA           |   COPY leggero.lg_vinsights (id, name, description, vi_type, option_def, query_id, data_def, child_id, email_def) FROM stdin;
    leggero          admin    false    304   �@      �          0    313574    report_configurations 
   TABLE DATA           �   COPY leggero.report_configurations (id, report_configurations2version, write_configuration, status, tablename, report_configuration_name) FROM stdin;
    leggero          postgres    false    305   HO      �          0    313583    run_schedule_rules 
   TABLE DATA           �   COPY leggero.run_schedule_rules (id, rule_name, rule_id, status, rule_description, rule_json, create_datetime, lastchange_datetime, schedule2pipeline) FROM stdin;
    leggero          postgres    false    307   X      �          0    313591    schedule_instance 
   TABLE DATA           �   COPY leggero.schedule_instance (id, instance2schedule, create_datetime, lastchange_datetime, prev_rundate, prev_runtime, schedule_ins2pipeline_ins) FROM stdin;
    leggero          postgres    false    309   2X      �          0    313596    write_to_db_configuration 
   TABLE DATA             COPY leggero.write_to_db_configuration (id, write_db_config2version, tablename, status, decision_filter_config_fe, decision_filter_config_be, column_config, db_meta_config, output_column_config, create_datetime, lastchange_datetime, con_string_name, configuration_name) FROM stdin;
    leggero          postgres    false    311   OX      �           0    0    Communication_Templates_id_seq    SEQUENCE SET     P   SELECT pg_catalog.setval('leggero."Communication_Templates_id_seq"', 1, false);
          leggero          postgres    false    199            �           0    0    api_definition_id_seq    SEQUENCE SET     E   SELECT pg_catalog.setval('leggero.api_definition_id_seq', 1, false);
          leggero          postgres    false    201            �           0    0    api_writer_audit_id_seq    SEQUENCE SET     G   SELECT pg_catalog.setval('leggero.api_writer_audit_id_seq', 1, false);
          leggero          postgres    false    203            �           0    0    at_email_configuration_id_seq    SEQUENCE SET     M   SELECT pg_catalog.setval('leggero.at_email_configuration_id_seq', 1, false);
          leggero          postgres    false    205            �           0    0    connections_con_id_seq    SEQUENCE SET     F   SELECT pg_catalog.setval('leggero.connections_con_id_seq', 1, false);
          leggero          admin    false    206            �           0    0    datasource_ds_id_seq    SEQUENCE SET     D   SELECT pg_catalog.setval('leggero.datasource_ds_id_seq', 1, false);
          leggero          admin    false    208            �           0    0    db_writer_audit_id_seq    SEQUENCE SET     F   SELECT pg_catalog.setval('leggero.db_writer_audit_id_seq', 1, false);
          leggero          postgres    false    211                        0    0    dds_api_writer_id_seq    SEQUENCE SET     E   SELECT pg_catalog.setval('leggero.dds_api_writer_id_seq', 1, false);
          leggero          postgres    false    213                       0    0    dds_custom_functions_id_seq    SEQUENCE SET     J   SELECT pg_catalog.setval('leggero.dds_custom_functions_id_seq', 4, true);
          leggero          admin    false    215                       0    0    dds_filter_functions_id_seq    SEQUENCE SET     K   SELECT pg_catalog.setval('leggero.dds_filter_functions_id_seq', 1, false);
          leggero          admin    false    217                       0    0    dds_ftp_definition_id_seq    SEQUENCE SET     I   SELECT pg_catalog.setval('leggero.dds_ftp_definition_id_seq', 1, false);
          leggero          postgres    false    219                       0    0    dds_global_imports_id_seq    SEQUENCE SET     I   SELECT pg_catalog.setval('leggero.dds_global_imports_id_seq', 1, false);
          leggero          admin    false    221                       0    0    dds_mapping_id_seq    SEQUENCE SET     A   SELECT pg_catalog.setval('leggero.dds_mapping_id_seq', 6, true);
          leggero          postgres    false    223                       0    0    dds_pipe_ins_log_seq    SEQUENCE SET     D   SELECT pg_catalog.setval('leggero.dds_pipe_ins_log_seq', 1, false);
          leggero          postgres    false    224                       0    0    dds_pipeline_activity_defs_seq    SEQUENCE SET     O   SELECT pg_catalog.setval('leggero.dds_pipeline_activity_defs_seq', 137, true);
          leggero          postgres    false    228                       0    0     dds_pipeline_activity_params_seq    SEQUENCE SET     P   SELECT pg_catalog.setval('leggero.dds_pipeline_activity_params_seq', 1, false);
          leggero          postgres    false    230            	           0    0    dds_pipeline_instance_seq    SEQUENCE SET     I   SELECT pg_catalog.setval('leggero.dds_pipeline_instance_seq', 1, false);
          leggero          postgres    false    231            
           0    0    dds_pipeline_metadata_seq    SEQUENCE SET     I   SELECT pg_catalog.setval('leggero.dds_pipeline_metadata_seq', 1, false);
          leggero          postgres    false    233                       0    0    dds_pipeline_seq    SEQUENCE SET     @   SELECT pg_catalog.setval('leggero.dds_pipeline_seq', 1, false);
          leggero          postgres    false    226                       0    0    dds_project_versions_id_seq    SEQUENCE SET     J   SELECT pg_catalog.setval('leggero.dds_project_versions_id_seq', 6, true);
          leggero          admin    false    236                       0    0    dds_projects_id_seq    SEQUENCE SET     B   SELECT pg_catalog.setval('leggero.dds_projects_id_seq', 4, true);
          leggero          admin    false    237                       0    0    dds_schema_id_seq    SEQUENCE SET     B   SELECT pg_catalog.setval('leggero.dds_schema_id_seq', 118, true);
          leggero          admin    false    239                       0    0    dds_script_definition_id_seq    SEQUENCE SET     L   SELECT pg_catalog.setval('leggero.dds_script_definition_id_seq', 1, false);
          leggero          postgres    false    241                       0    0 %   dds_script_definition_instance_id_seq    SEQUENCE SET     U   SELECT pg_catalog.setval('leggero.dds_script_definition_instance_id_seq', 1, false);
          leggero          postgres    false    243                       0    0    dds_script_executors_id_seq    SEQUENCE SET     K   SELECT pg_catalog.setval('leggero.dds_script_executors_id_seq', 1, false);
          leggero          postgres    false    245                       0    0    email_configuration_id_seq    SEQUENCE SET     J   SELECT pg_catalog.setval('leggero.email_configuration_id_seq', 1, false);
          leggero          postgres    false    247                       0    0    email_read_param_config_id_seq    SEQUENCE SET     N   SELECT pg_catalog.setval('leggero.email_read_param_config_id_seq', 1, false);
          leggero          postgres    false    249                       0    0    lg_aofrmqry_id_seq    SEQUENCE SET     B   SELECT pg_catalog.setval('leggero.lg_aofrmqry_id_seq', 1, false);
          leggero          admin    false    250                       0    0    lg_columns_id_seq    SEQUENCE SET     A   SELECT pg_catalog.setval('leggero.lg_columns_id_seq', 1, false);
          leggero          admin    false    252                       0    0    lg_composite_widget_seq    SEQUENCE SET     G   SELECT pg_catalog.setval('leggero.lg_composite_widget_seq', 37, true);
          leggero          postgres    false    254                       0    0    lg_dashboards_id_seq    SEQUENCE SET     D   SELECT pg_catalog.setval('leggero.lg_dashboards_id_seq', 44, true);
          leggero          admin    false    256                       0    0    lg_department_id_seq    SEQUENCE SET     D   SELECT pg_catalog.setval('leggero.lg_department_id_seq', 1, false);
          leggero          admin    false    258                       0    0    lg_dshb_group_id_seq    SEQUENCE SET     D   SELECT pg_catalog.setval('leggero.lg_dshb_group_id_seq', 17, true);
          leggero          admin    false    261                       0    0    lg_dshb_group_user_id_seq    SEQUENCE SET     J   SELECT pg_catalog.setval('leggero.lg_dshb_group_user_id_seq', 185, true);
          leggero          admin    false    263                       0    0    lg_dshbgroup_dashboard_id_seq    SEQUENCE SET     M   SELECT pg_catalog.setval('leggero.lg_dshbgroup_dashboard_id_seq', 40, true);
          leggero          admin    false    265                       0    0    lg_employee_id_seq    SEQUENCE SET     B   SELECT pg_catalog.setval('leggero.lg_employee_id_seq', 1, false);
          leggero          admin    false    267                       0    0    lg_query_id_seq    SEQUENCE SET     @   SELECT pg_catalog.setval('leggero.lg_query_id_seq', 154, true);
          leggero          admin    false    271                       0    0 "   lg_rep_dashboard_group_to_user_seq    SEQUENCE SET     R   SELECT pg_catalog.setval('leggero.lg_rep_dashboard_group_to_user_seq', 38, true);
          leggero          postgres    false    273                       0    0 !   lg_rep_dashboard_to_dashgroup_seq    SEQUENCE SET     P   SELECT pg_catalog.setval('leggero.lg_rep_dashboard_to_dashgroup_seq', 4, true);
          leggero          postgres    false    275                        0    0    lg_report_dashboard_group_seq    SEQUENCE SET     L   SELECT pg_catalog.setval('leggero.lg_report_dashboard_group_seq', 3, true);
          leggero          postgres    false    285            !           0    0    lg_report_dashboard_seq    SEQUENCE SET     F   SELECT pg_catalog.setval('leggero.lg_report_dashboard_seq', 4, true);
          leggero          postgres    false    283            "           0    0    lg_report_group_id_seq    SEQUENCE SET     F   SELECT pg_catalog.setval('leggero.lg_report_group_id_seq', 1, false);
          leggero          admin    false    277            #           0    0    lg_reports_id_seq    SEQUENCE SET     A   SELECT pg_catalog.setval('leggero.lg_reports_id_seq', 20, true);
          leggero          admin    false    279            $           0    0    lg_rgroup_report_id_seq    SEQUENCE SET     G   SELECT pg_catalog.setval('leggero.lg_rgroup_report_id_seq', 1, false);
          leggero          admin    false    281            %           0    0    lg_rgroup_user_id_seq    SEQUENCE SET     E   SELECT pg_catalog.setval('leggero.lg_rgroup_user_id_seq', 1, false);
          leggero          admin    false    287            &           0    0    lg_tables_id_seq    SEQUENCE SET     @   SELECT pg_catalog.setval('leggero.lg_tables_id_seq', 1, false);
          leggero          admin    false    293            '           0    0    lg_user_grp_id_seq    SEQUENCE SET     B   SELECT pg_catalog.setval('leggero.lg_user_grp_id_seq', 1, false);
          leggero          admin    false    295            (           0    0    lg_user_home_dashboard_seq    SEQUENCE SET     J   SELECT pg_catalog.setval('leggero.lg_user_home_dashboard_seq', 15, true);
          leggero          postgres    false    291            )           0    0    lg_user_id_seq    SEQUENCE SET     ?   SELECT pg_catalog.setval('leggero.lg_user_id_seq', 135, true);
          leggero          admin    false    289            *           0    0    lg_view_cols_id_seq    SEQUENCE SET     C   SELECT pg_catalog.setval('leggero.lg_view_cols_id_seq', 1, false);
          leggero          admin    false    297            +           0    0    lg_view_tables_id_seq    SEQUENCE SET     E   SELECT pg_catalog.setval('leggero.lg_view_tables_id_seq', 1, false);
          leggero          admin    false    299            ,           0    0    lg_views_id_seq    SEQUENCE SET     ?   SELECT pg_catalog.setval('leggero.lg_views_id_seq', 1, false);
          leggero          admin    false    301            -           0    0    lg_vinsights_id_seq    SEQUENCE SET     C   SELECT pg_catalog.setval('leggero.lg_vinsights_id_seq', 52, true);
          leggero          admin    false    303            .           0    0    report_configurations_id_seq    SEQUENCE SET     K   SELECT pg_catalog.setval('leggero.report_configurations_id_seq', 5, true);
          leggero          postgres    false    306            /           0    0    run_schedule_rules_id_seq    SEQUENCE SET     I   SELECT pg_catalog.setval('leggero.run_schedule_rules_id_seq', 1, false);
          leggero          postgres    false    308            0           0    0    schedule_instance_id_seq    SEQUENCE SET     H   SELECT pg_catalog.setval('leggero.schedule_instance_id_seq', 1, false);
          leggero          postgres    false    310            1           0    0     write_to_db_configuration_id_seq    SEQUENCE SET     P   SELECT pg_catalog.setval('leggero.write_to_db_configuration_id_seq', 1, false);
          leggero          postgres    false    312                       2606    313668     api_definition api_defination_pk 
   CONSTRAINT     _   ALTER TABLE ONLY leggero.api_definition
    ADD CONSTRAINT api_defination_pk PRIMARY KEY (id);
 K   ALTER TABLE ONLY leggero.api_definition DROP CONSTRAINT api_defination_pk;
       leggero            postgres    false    200                       2606    313670 $   api_writer_audit api_writer_audit_pk 
   CONSTRAINT     c   ALTER TABLE ONLY leggero.api_writer_audit
    ADD CONSTRAINT api_writer_audit_pk PRIMARY KEY (id);
 O   ALTER TABLE ONLY leggero.api_writer_audit DROP CONSTRAINT api_writer_audit_pk;
       leggero            postgres    false    202                       2606    313672 0   at_email_configuration at_email_configuration_pk 
   CONSTRAINT     o   ALTER TABLE ONLY leggero.at_email_configuration
    ADD CONSTRAINT at_email_configuration_pk PRIMARY KEY (id);
 [   ALTER TABLE ONLY leggero.at_email_configuration DROP CONSTRAINT at_email_configuration_pk;
       leggero            postgres    false    204                       2606    313674 $   Communication_Templates comm_temp_pk 
   CONSTRAINT     e   ALTER TABLE ONLY leggero."Communication_Templates"
    ADD CONSTRAINT comm_temp_pk PRIMARY KEY (id);
 Q   ALTER TABLE ONLY leggero."Communication_Templates" DROP CONSTRAINT comm_temp_pk;
       leggero            postgres    false    198            +           2606    313676 (   dds_custom_functions custom_functions_pk 
   CONSTRAINT     g   ALTER TABLE ONLY leggero.dds_custom_functions
    ADD CONSTRAINT custom_functions_pk PRIMARY KEY (id);
 S   ALTER TABLE ONLY leggero.dds_custom_functions DROP CONSTRAINT custom_functions_pk;
       leggero            admin    false    214            '           2606    313678 "   db_writer_audit db_writer_audit_pk 
   CONSTRAINT     a   ALTER TABLE ONLY leggero.db_writer_audit
    ADD CONSTRAINT db_writer_audit_pk PRIMARY KEY (id);
 M   ALTER TABLE ONLY leggero.db_writer_audit DROP CONSTRAINT db_writer_audit_pk;
       leggero            postgres    false    210            )           2606    313680     dds_api_writer dds_api_writer_pk 
   CONSTRAINT     _   ALTER TABLE ONLY leggero.dds_api_writer
    ADD CONSTRAINT dds_api_writer_pk PRIMARY KEY (id);
 K   ALTER TABLE ONLY leggero.dds_api_writer DROP CONSTRAINT dds_api_writer_pk;
       leggero            postgres    false    212            -           2606    313682 ,   dds_filter_functions dds_filter_functions_pk 
   CONSTRAINT     k   ALTER TABLE ONLY leggero.dds_filter_functions
    ADD CONSTRAINT dds_filter_functions_pk PRIMARY KEY (id);
 W   ALTER TABLE ONLY leggero.dds_filter_functions DROP CONSTRAINT dds_filter_functions_pk;
       leggero            admin    false    216            /           2606    313684 (   dds_ftp_definition dds_ftp_definition_pk 
   CONSTRAINT     g   ALTER TABLE ONLY leggero.dds_ftp_definition
    ADD CONSTRAINT dds_ftp_definition_pk PRIMARY KEY (id);
 S   ALTER TABLE ONLY leggero.dds_ftp_definition DROP CONSTRAINT dds_ftp_definition_pk;
       leggero            postgres    false    218            1           2606    313686 (   dds_global_imports dds_global_imports_pk 
   CONSTRAINT     g   ALTER TABLE ONLY leggero.dds_global_imports
    ADD CONSTRAINT dds_global_imports_pk PRIMARY KEY (id);
 S   ALTER TABLE ONLY leggero.dds_global_imports DROP CONSTRAINT dds_global_imports_pk;
       leggero            admin    false    220            3           2606    313688    dds_mapping dds_mapping_pk 
   CONSTRAINT     Y   ALTER TABLE ONLY leggero.dds_mapping
    ADD CONSTRAINT dds_mapping_pk PRIMARY KEY (id);
 E   ALTER TABLE ONLY leggero.dds_mapping DROP CONSTRAINT dds_mapping_pk;
       leggero            postgres    false    222            5           2606    313690 $   dds_pipe_ins_log dds_pipe_ins_log_pk 
   CONSTRAINT     c   ALTER TABLE ONLY leggero.dds_pipe_ins_log
    ADD CONSTRAINT dds_pipe_ins_log_pk PRIMARY KEY (id);
 O   ALTER TABLE ONLY leggero.dds_pipe_ins_log DROP CONSTRAINT dds_pipe_ins_log_pk;
       leggero            postgres    false    225            9           2606    313692 8   dds_pipeline_activity_defs dds_pipeline_activity_defs_pk 
   CONSTRAINT     w   ALTER TABLE ONLY leggero.dds_pipeline_activity_defs
    ADD CONSTRAINT dds_pipeline_activity_defs_pk PRIMARY KEY (id);
 c   ALTER TABLE ONLY leggero.dds_pipeline_activity_defs DROP CONSTRAINT dds_pipeline_activity_defs_pk;
       leggero            postgres    false    229            ;           2606    313694 .   dds_pipeline_instance dds_pipeline_instance_pk 
   CONSTRAINT     m   ALTER TABLE ONLY leggero.dds_pipeline_instance
    ADD CONSTRAINT dds_pipeline_instance_pk PRIMARY KEY (id);
 Y   ALTER TABLE ONLY leggero.dds_pipeline_instance DROP CONSTRAINT dds_pipeline_instance_pk;
       leggero            postgres    false    232            7           2606    313696    dds_pipeline dds_pipeline_pk 
   CONSTRAINT     [   ALTER TABLE ONLY leggero.dds_pipeline
    ADD CONSTRAINT dds_pipeline_pk PRIMARY KEY (id);
 G   ALTER TABLE ONLY leggero.dds_pipeline DROP CONSTRAINT dds_pipeline_pk;
       leggero            postgres    false    227            A           2606    313698    dds_schema dds_schema_pk 
   CONSTRAINT     W   ALTER TABLE ONLY leggero.dds_schema
    ADD CONSTRAINT dds_schema_pk PRIMARY KEY (id);
 C   ALTER TABLE ONLY leggero.dds_schema DROP CONSTRAINT dds_schema_pk;
       leggero            admin    false    238            G           2606    313700 @   dds_script_definition_instance dds_script_defenition_instance_pk 
   CONSTRAINT        ALTER TABLE ONLY leggero.dds_script_definition_instance
    ADD CONSTRAINT dds_script_defenition_instance_pk PRIMARY KEY (id);
 k   ALTER TABLE ONLY leggero.dds_script_definition_instance DROP CONSTRAINT dds_script_defenition_instance_pk;
       leggero            postgres    false    242            C           2606    313702 .   dds_script_definition dds_script_defenition_pk 
   CONSTRAINT     m   ALTER TABLE ONLY leggero.dds_script_definition
    ADD CONSTRAINT dds_script_defenition_pk PRIMARY KEY (id);
 Y   ALTER TABLE ONLY leggero.dds_script_definition DROP CONSTRAINT dds_script_defenition_pk;
       leggero            postgres    false    240            I           2606    313704 ,   dds_script_executors dds_script_executors_pk 
   CONSTRAINT     k   ALTER TABLE ONLY leggero.dds_script_executors
    ADD CONSTRAINT dds_script_executors_pk PRIMARY KEY (id);
 W   ALTER TABLE ONLY leggero.dds_script_executors DROP CONSTRAINT dds_script_executors_pk;
       leggero            postgres    false    244            O           2606    313706 )   email_configuration email_config_name_unq 
   CONSTRAINT     e   ALTER TABLE ONLY leggero.email_configuration
    ADD CONSTRAINT email_config_name_unq UNIQUE (name);
 T   ALTER TABLE ONLY leggero.email_configuration DROP CONSTRAINT email_config_name_unq;
       leggero            postgres    false    246            Q           2606    313708 *   email_configuration email_configuration_pk 
   CONSTRAINT     i   ALTER TABLE ONLY leggero.email_configuration
    ADD CONSTRAINT email_configuration_pk PRIMARY KEY (id);
 U   ALTER TABLE ONLY leggero.email_configuration DROP CONSTRAINT email_configuration_pk;
       leggero            postgres    false    246            S           2606    313710 2   email_read_param_config email_read_param_config_pk 
   CONSTRAINT     q   ALTER TABLE ONLY leggero.email_read_param_config
    ADD CONSTRAINT email_read_param_config_pk PRIMARY KEY (id);
 ]   ALTER TABLE ONLY leggero.email_read_param_config DROP CONSTRAINT email_read_param_config_pk;
       leggero            postgres    false    248            K           2606    313712 )   dds_script_executors executor_name_unique 
   CONSTRAINT     e   ALTER TABLE ONLY leggero.dds_script_executors
    ADD CONSTRAINT executor_name_unique UNIQUE (name);
 T   ALTER TABLE ONLY leggero.dds_script_executors DROP CONSTRAINT executor_name_unique;
       leggero            postgres    false    244            M           2606    313714 )   dds_script_executors executor_path_unique 
   CONSTRAINT     e   ALTER TABLE ONLY leggero.dds_script_executors
    ADD CONSTRAINT executor_path_unique UNIQUE (path);
 T   ALTER TABLE ONLY leggero.dds_script_executors DROP CONSTRAINT executor_path_unique;
       leggero            postgres    false    244            z           2606    313716 (   lg_rep_dashboard_to_dashgroup id_primary 
   CONSTRAINT     g   ALTER TABLE ONLY leggero.lg_rep_dashboard_to_dashgroup
    ADD CONSTRAINT id_primary PRIMARY KEY (id);
 S   ALTER TABLE ONLY leggero.lg_rep_dashboard_to_dashgroup DROP CONSTRAINT id_primary;
       leggero            postgres    false    276            x           2606    313718 +   lg_rep_dashboard_group_to_user id_primary_1 
   CONSTRAINT     j   ALTER TABLE ONLY leggero.lg_rep_dashboard_group_to_user
    ADD CONSTRAINT id_primary_1 PRIMARY KEY (id);
 V   ALTER TABLE ONLY leggero.lg_rep_dashboard_group_to_user DROP CONSTRAINT id_primary_1;
       leggero            postgres    false    274            �           2606    313720    lg_user_home_dashboard idx 
   CONSTRAINT     Y   ALTER TABLE ONLY leggero.lg_user_home_dashboard
    ADD CONSTRAINT idx PRIMARY KEY (id);
 E   ALTER TABLE ONLY leggero.lg_user_home_dashboard DROP CONSTRAINT idx;
       leggero            postgres    false    292            !           2606    313722    connections idx_64051_primary 
   CONSTRAINT     `   ALTER TABLE ONLY leggero.connections
    ADD CONSTRAINT idx_64051_primary PRIMARY KEY (con_id);
 H   ALTER TABLE ONLY leggero.connections DROP CONSTRAINT idx_64051_primary;
       leggero            admin    false    207            %           2606    313724    datasource idx_64057_primary 
   CONSTRAINT     ^   ALTER TABLE ONLY leggero.datasource
    ADD CONSTRAINT idx_64057_primary PRIMARY KEY (ds_id);
 G   ALTER TABLE ONLY leggero.datasource DROP CONSTRAINT idx_64057_primary;
       leggero            admin    false    209            V           2606    313726    lg_aofrmqry idx_64066_primary 
   CONSTRAINT     \   ALTER TABLE ONLY leggero.lg_aofrmqry
    ADD CONSTRAINT idx_64066_primary PRIMARY KEY (id);
 H   ALTER TABLE ONLY leggero.lg_aofrmqry DROP CONSTRAINT idx_64066_primary;
       leggero            admin    false    251            Z           2606    313728    lg_columns idx_64072_primary 
   CONSTRAINT     [   ALTER TABLE ONLY leggero.lg_columns
    ADD CONSTRAINT idx_64072_primary PRIMARY KEY (id);
 G   ALTER TABLE ONLY leggero.lg_columns DROP CONSTRAINT idx_64072_primary;
       leggero            admin    false    253            ^           2606    313730    lg_dashboards idx_64080_primary 
   CONSTRAINT     ^   ALTER TABLE ONLY leggero.lg_dashboards
    ADD CONSTRAINT idx_64080_primary PRIMARY KEY (id);
 J   ALTER TABLE ONLY leggero.lg_dashboards DROP CONSTRAINT idx_64080_primary;
       leggero            admin    false    257            `           2606    313732    lg_department idx_64089_primary 
   CONSTRAINT     ^   ALTER TABLE ONLY leggero.lg_department
    ADD CONSTRAINT idx_64089_primary PRIMARY KEY (id);
 J   ALTER TABLE ONLY leggero.lg_department DROP CONSTRAINT idx_64089_primary;
       leggero            admin    false    259            l           2606    313734 (   lg_dshbgroup_dashboard idx_64098_primary 
   CONSTRAINT     g   ALTER TABLE ONLY leggero.lg_dshbgroup_dashboard
    ADD CONSTRAINT idx_64098_primary PRIMARY KEY (id);
 S   ALTER TABLE ONLY leggero.lg_dshbgroup_dashboard DROP CONSTRAINT idx_64098_primary;
       leggero            admin    false    266            d           2606    313736    lg_dshb_group idx_64104_primary 
   CONSTRAINT     ^   ALTER TABLE ONLY leggero.lg_dshb_group
    ADD CONSTRAINT idx_64104_primary PRIMARY KEY (id);
 J   ALTER TABLE ONLY leggero.lg_dshb_group DROP CONSTRAINT idx_64104_primary;
       leggero            admin    false    262            h           2606    313738 $   lg_dshb_group_user idx_64110_primary 
   CONSTRAINT     c   ALTER TABLE ONLY leggero.lg_dshb_group_user
    ADD CONSTRAINT idx_64110_primary PRIMARY KEY (id);
 O   ALTER TABLE ONLY leggero.lg_dshb_group_user DROP CONSTRAINT idx_64110_primary;
       leggero            admin    false    264            n           2606    313740    lg_employee idx_64116_primary 
   CONSTRAINT     \   ALTER TABLE ONLY leggero.lg_employee
    ADD CONSTRAINT idx_64116_primary PRIMARY KEY (id);
 H   ALTER TABLE ONLY leggero.lg_employee DROP CONSTRAINT idx_64116_primary;
       leggero            admin    false    268            t           2606    313742    lg_jobstore idx_64123_primary 
   CONSTRAINT     \   ALTER TABLE ONLY leggero.lg_jobstore
    ADD CONSTRAINT idx_64123_primary PRIMARY KEY (id);
 H   ALTER TABLE ONLY leggero.lg_jobstore DROP CONSTRAINT idx_64123_primary;
       leggero            admin    false    270            v           2606    313744    lg_query idx_64131_primary 
   CONSTRAINT     Y   ALTER TABLE ONLY leggero.lg_query
    ADD CONSTRAINT idx_64131_primary PRIMARY KEY (id);
 E   ALTER TABLE ONLY leggero.lg_query DROP CONSTRAINT idx_64131_primary;
       leggero            admin    false    272            ~           2606    313746    lg_reports idx_64141_primary 
   CONSTRAINT     [   ALTER TABLE ONLY leggero.lg_reports
    ADD CONSTRAINT idx_64141_primary PRIMARY KEY (id);
 G   ALTER TABLE ONLY leggero.lg_reports DROP CONSTRAINT idx_64141_primary;
       leggero            admin    false    280            |           2606    313748 !   lg_report_group idx_64150_primary 
   CONSTRAINT     `   ALTER TABLE ONLY leggero.lg_report_group
    ADD CONSTRAINT idx_64150_primary PRIMARY KEY (id);
 L   ALTER TABLE ONLY leggero.lg_report_group DROP CONSTRAINT idx_64150_primary;
       leggero            admin    false    278            �           2606    313750 "   lg_rgroup_report idx_64156_primary 
   CONSTRAINT     a   ALTER TABLE ONLY leggero.lg_rgroup_report
    ADD CONSTRAINT idx_64156_primary PRIMARY KEY (id);
 M   ALTER TABLE ONLY leggero.lg_rgroup_report DROP CONSTRAINT idx_64156_primary;
       leggero            admin    false    282            �           2606    313752     lg_rgroup_user idx_64162_primary 
   CONSTRAINT     _   ALTER TABLE ONLY leggero.lg_rgroup_user
    ADD CONSTRAINT idx_64162_primary PRIMARY KEY (id);
 K   ALTER TABLE ONLY leggero.lg_rgroup_user DROP CONSTRAINT idx_64162_primary;
       leggero            admin    false    288            �           2606    313754    lg_tables idx_64168_primary 
   CONSTRAINT     Z   ALTER TABLE ONLY leggero.lg_tables
    ADD CONSTRAINT idx_64168_primary PRIMARY KEY (id);
 F   ALTER TABLE ONLY leggero.lg_tables DROP CONSTRAINT idx_64168_primary;
       leggero            admin    false    294            �           2606    313756    lg_user idx_64174_primary 
   CONSTRAINT     X   ALTER TABLE ONLY leggero.lg_user
    ADD CONSTRAINT idx_64174_primary PRIMARY KEY (id);
 D   ALTER TABLE ONLY leggero.lg_user DROP CONSTRAINT idx_64174_primary;
       leggero            admin    false    290            �           2606    313758    lg_user_grp idx_64183_primary 
   CONSTRAINT     \   ALTER TABLE ONLY leggero.lg_user_grp
    ADD CONSTRAINT idx_64183_primary PRIMARY KEY (id);
 H   ALTER TABLE ONLY leggero.lg_user_grp DROP CONSTRAINT idx_64183_primary;
       leggero            admin    false    296            �           2606    313760    lg_views idx_64189_primary 
   CONSTRAINT     Y   ALTER TABLE ONLY leggero.lg_views
    ADD CONSTRAINT idx_64189_primary PRIMARY KEY (id);
 E   ALTER TABLE ONLY leggero.lg_views DROP CONSTRAINT idx_64189_primary;
       leggero            admin    false    302            �           2606    313762    lg_view_cols idx_64195_primary 
   CONSTRAINT     ]   ALTER TABLE ONLY leggero.lg_view_cols
    ADD CONSTRAINT idx_64195_primary PRIMARY KEY (id);
 I   ALTER TABLE ONLY leggero.lg_view_cols DROP CONSTRAINT idx_64195_primary;
       leggero            admin    false    298            �           2606    313764     lg_view_tables idx_64201_primary 
   CONSTRAINT     _   ALTER TABLE ONLY leggero.lg_view_tables
    ADD CONSTRAINT idx_64201_primary PRIMARY KEY (id);
 K   ALTER TABLE ONLY leggero.lg_view_tables DROP CONSTRAINT idx_64201_primary;
       leggero            admin    false    300            �           2606    313766    lg_vinsights idx_64207_primary 
   CONSTRAINT     ]   ALTER TABLE ONLY leggero.lg_vinsights
    ADD CONSTRAINT idx_64207_primary PRIMARY KEY (id);
 I   ALTER TABLE ONLY leggero.lg_vinsights DROP CONSTRAINT idx_64207_primary;
       leggero            admin    false    304            E           2606    313768 !   dds_script_definition name_unique 
   CONSTRAINT     ]   ALTER TABLE ONLY leggero.dds_script_definition
    ADD CONSTRAINT name_unique UNIQUE (name);
 L   ALTER TABLE ONLY leggero.dds_script_definition DROP CONSTRAINT name_unique;
       leggero            postgres    false    240            �           2606    313770    lg_report_dashboard_group pk_id 
   CONSTRAINT     ^   ALTER TABLE ONLY leggero.lg_report_dashboard_group
    ADD CONSTRAINT pk_id PRIMARY KEY (id);
 J   ALTER TABLE ONLY leggero.lg_report_dashboard_group DROP CONSTRAINT pk_id;
       leggero            postgres    false    286            \           2606    313772    lg_composite_widgets pk_id_1 
   CONSTRAINT     [   ALTER TABLE ONLY leggero.lg_composite_widgets
    ADD CONSTRAINT pk_id_1 PRIMARY KEY (id);
 G   ALTER TABLE ONLY leggero.lg_composite_widgets DROP CONSTRAINT pk_id_1;
       leggero            postgres    false    255            �           2606    313774    lg_report_dashboard pk_idx 
   CONSTRAINT     Y   ALTER TABLE ONLY leggero.lg_report_dashboard
    ADD CONSTRAINT pk_idx PRIMARY KEY (id);
 E   ALTER TABLE ONLY leggero.lg_report_dashboard DROP CONSTRAINT pk_idx;
       leggero            postgres    false    284            ?           2606    313776    dds_projects projects_pk 
   CONSTRAINT     W   ALTER TABLE ONLY leggero.dds_projects
    ADD CONSTRAINT projects_pk PRIMARY KEY (id);
 C   ALTER TABLE ONLY leggero.dds_projects DROP CONSTRAINT projects_pk;
       leggero            admin    false    235            �           2606    313778 .   report_configurations report_configurations_pk 
   CONSTRAINT     m   ALTER TABLE ONLY leggero.report_configurations
    ADD CONSTRAINT report_configurations_pk PRIMARY KEY (id);
 Y   ALTER TABLE ONLY leggero.report_configurations DROP CONSTRAINT report_configurations_pk;
       leggero            postgres    false    305            �           2606    313780 (   run_schedule_rules run_schedule_rules_pk 
   CONSTRAINT     g   ALTER TABLE ONLY leggero.run_schedule_rules
    ADD CONSTRAINT run_schedule_rules_pk PRIMARY KEY (id);
 S   ALTER TABLE ONLY leggero.run_schedule_rules DROP CONSTRAINT run_schedule_rules_pk;
       leggero            postgres    false    307            �           2606    313782 &   schedule_instance schedule_instance_pk 
   CONSTRAINT     e   ALTER TABLE ONLY leggero.schedule_instance
    ADD CONSTRAINT schedule_instance_pk PRIMARY KEY (id);
 Q   ALTER TABLE ONLY leggero.schedule_instance DROP CONSTRAINT schedule_instance_pk;
       leggero            postgres    false    309            =           2606    313784     dds_project_versions versions_pk 
   CONSTRAINT     _   ALTER TABLE ONLY leggero.dds_project_versions
    ADD CONSTRAINT versions_pk PRIMARY KEY (id);
 K   ALTER TABLE ONLY leggero.dds_project_versions DROP CONSTRAINT versions_pk;
       leggero            admin    false    234            �           2606    313786 6   write_to_db_configuration write_to_db_configuration_pk 
   CONSTRAINT     u   ALTER TABLE ONLY leggero.write_to_db_configuration
    ADD CONSTRAINT write_to_db_configuration_pk PRIMARY KEY (id);
 a   ALTER TABLE ONLY leggero.write_to_db_configuration DROP CONSTRAINT write_to_db_configuration_pk;
       leggero            postgres    false    311            "           1259    313787 '   idx_64057_fk_datasource_connections_idx    INDEX        CREATE INDEX idx_64057_fk_datasource_connections_idx ON leggero.datasource USING btree (connection_id) WITH (fillfactor='90');
 <   DROP INDEX leggero.idx_64057_fk_datasource_connections_idx;
       leggero            admin    false    209            #           1259    313788    idx_64057_name_unique    INDEX     k   CREATE UNIQUE INDEX idx_64057_name_unique ON leggero.datasource USING btree (name) WITH (fillfactor='90');
 *   DROP INDEX leggero.idx_64057_name_unique;
       leggero            admin    false    209            T           1259    313789    idx_64066_name_unique    INDEX     l   CREATE UNIQUE INDEX idx_64066_name_unique ON leggero.lg_aofrmqry USING btree (name) WITH (fillfactor='90');
 *   DROP INDEX leggero.idx_64066_name_unique;
       leggero            admin    false    251            W           1259    313790    idx_64066_queryid_idx    INDEX     i   CREATE INDEX idx_64066_queryid_idx ON leggero.lg_aofrmqry USING btree (query_id) WITH (fillfactor='90');
 *   DROP INDEX leggero.idx_64066_queryid_idx;
       leggero            admin    false    251            X           1259    313791 &   idx_64072_fk_lg_columns_lg_tables1_idx    INDEX     z   CREATE INDEX idx_64072_fk_lg_columns_lg_tables1_idx ON leggero.lg_columns USING btree (parent_id) WITH (fillfactor='90');
 ;   DROP INDEX leggero.idx_64072_fk_lg_columns_lg_tables1_idx;
       leggero            admin    false    253            a           1259    313792    idx_64093_dept_prd    INDEX     n   CREATE INDEX idx_64093_dept_prd ON leggero.lg_department_period USING btree (dept_id) WITH (fillfactor='90');
 '   DROP INDEX leggero.idx_64093_dept_prd;
       leggero            admin    false    260            b           1259    313793    idx_64093_emp_prd    INDEX     l   CREATE INDEX idx_64093_emp_prd ON leggero.lg_department_period USING btree (emp_id) WITH (fillfactor='90');
 &   DROP INDEX leggero.idx_64093_emp_prd;
       leggero            admin    false    260            i           1259    313794    idx_64098_fk_dashboard_idx    INDEX     }   CREATE INDEX idx_64098_fk_dashboard_idx ON leggero.lg_dshbgroup_dashboard USING btree (dashboard_id) WITH (fillfactor='90');
 /   DROP INDEX leggero.idx_64098_fk_dashboard_idx;
       leggero            admin    false    266            j           1259    313795    idx_64098_fk_dshbgroup_idx    INDEX     }   CREATE INDEX idx_64098_fk_dshbgroup_idx ON leggero.lg_dshbgroup_dashboard USING btree (dshbgroup_id) WITH (fillfactor='90');
 /   DROP INDEX leggero.idx_64098_fk_dshbgroup_idx;
       leggero            admin    false    266            e           1259    313796    idx_64110_fk_dshbgroup_idx    INDEX     z   CREATE INDEX idx_64110_fk_dshbgroup_idx ON leggero.lg_dshb_group_user USING btree (dshb_group_id) WITH (fillfactor='90');
 /   DROP INDEX leggero.idx_64110_fk_dshbgroup_idx;
       leggero            admin    false    264            f           1259    313797    idx_64110_fk_dshbuser_idx    INDEX     s   CREATE INDEX idx_64110_fk_dshbuser_idx ON leggero.lg_dshb_group_user USING btree (user_id) WITH (fillfactor='90');
 .   DROP INDEX leggero.idx_64110_fk_dshbuser_idx;
       leggero            admin    false    264            o           1259    313798    idx_64116_user_employee_fk    INDEX     o   CREATE INDEX idx_64116_user_employee_fk ON leggero.lg_employee USING btree (user_name) WITH (fillfactor='90');
 /   DROP INDEX leggero.idx_64116_user_employee_fk;
       leggero            admin    false    268            p           1259    313799    idx_64120_grp_prd    INDEX     e   CREATE INDEX idx_64120_grp_prd ON leggero.lg_grp_period USING btree (grp_id) WITH (fillfactor='90');
 &   DROP INDEX leggero.idx_64120_grp_prd;
       leggero            admin    false    269            q           1259    313800    idx_64120_user_prd    INDEX     g   CREATE INDEX idx_64120_user_prd ON leggero.lg_grp_period USING btree (user_id) WITH (fillfactor='90');
 '   DROP INDEX leggero.idx_64120_user_prd;
       leggero            admin    false    269            r           1259    313801 &   idx_64123_ix_lg_jobstore_next_run_time    INDEX        CREATE INDEX idx_64123_ix_lg_jobstore_next_run_time ON leggero.lg_jobstore USING btree (next_run_time) WITH (fillfactor='90');
 ;   DROP INDEX leggero.idx_64123_ix_lg_jobstore_next_run_time;
       leggero            admin    false    270                       1259    313802    idx_64141_queryrec_idx    INDEX     i   CREATE INDEX idx_64141_queryrec_idx ON leggero.lg_reports USING btree (query_id) WITH (fillfactor='90');
 +   DROP INDEX leggero.idx_64141_queryrec_idx;
       leggero            admin    false    280            �           1259    313803    idx_64156_fk_report_idx    INDEX     q   CREATE INDEX idx_64156_fk_report_idx ON leggero.lg_rgroup_report USING btree (report_id) WITH (fillfactor='90');
 ,   DROP INDEX leggero.idx_64156_fk_report_idx;
       leggero            admin    false    282            �           1259    313804    idx_64156_fk_reportgroup_idx    INDEX     v   CREATE INDEX idx_64156_fk_reportgroup_idx ON leggero.lg_rgroup_report USING btree (rgroup_id) WITH (fillfactor='90');
 1   DROP INDEX leggero.idx_64156_fk_reportgroup_idx;
       leggero            admin    false    282            �           1259    313805    idx_64162_fk_repgroup_idx    INDEX     q   CREATE INDEX idx_64162_fk_repgroup_idx ON leggero.lg_rgroup_user USING btree (rgroup_id) WITH (fillfactor='90');
 .   DROP INDEX leggero.idx_64162_fk_repgroup_idx;
       leggero            admin    false    288            �           1259    313806    idx_64162_fk_repuser_idx    INDEX     n   CREATE INDEX idx_64162_fk_repuser_idx ON leggero.lg_rgroup_user USING btree (user_id) WITH (fillfactor='90');
 -   DROP INDEX leggero.idx_64162_fk_repuser_idx;
       leggero            admin    false    288            �           1259    313807 &   idx_64168_fk_lg_tables_datasource1_idx    INDEX     ~   CREATE INDEX idx_64168_fk_lg_tables_datasource1_idx ON leggero.lg_tables USING btree (data_source_id) WITH (fillfactor='90');
 ;   DROP INDEX leggero.idx_64168_fk_lg_tables_datasource1_idx;
       leggero            admin    false    294            �           1259    313808    idx_64174_user_name_unique    INDEX     r   CREATE UNIQUE INDEX idx_64174_user_name_unique ON leggero.lg_user USING btree (user_name) WITH (fillfactor='90');
 /   DROP INDEX leggero.idx_64174_user_name_unique;
       leggero            admin    false    290            �           1259    313809 '   idx_64195_fk_lg_view_cols_lg_views1_idx    INDEX     }   CREATE INDEX idx_64195_fk_lg_view_cols_lg_views1_idx ON leggero.lg_view_cols USING btree (parent_id) WITH (fillfactor='90');
 <   DROP INDEX leggero.idx_64195_fk_lg_view_cols_lg_views1_idx;
       leggero            admin    false    298            �           1259    313810 +   idx_64201_fk_lg_view_tables_datasource1_idx    INDEX     �   CREATE INDEX idx_64201_fk_lg_view_tables_datasource1_idx ON leggero.lg_view_tables USING btree (join_ds1) WITH (fillfactor='90');
 @   DROP INDEX leggero.idx_64201_fk_lg_view_tables_datasource1_idx;
       leggero            admin    false    300            �           1259    313811 )   idx_64201_fk_lg_view_tables_lg_views1_idx    INDEX     �   CREATE INDEX idx_64201_fk_lg_view_tables_lg_views1_idx ON leggero.lg_view_tables USING btree (parent_id) WITH (fillfactor='90');
 >   DROP INDEX leggero.idx_64201_fk_lg_view_tables_lg_views1_idx;
       leggero            admin    false    300            �           1259    313812    idx_64207_queryrec_idx    INDEX     k   CREATE INDEX idx_64207_queryrec_idx ON leggero.lg_vinsights USING btree (query_id) WITH (fillfactor='90');
 +   DROP INDEX leggero.idx_64207_queryrec_idx;
       leggero            admin    false    304            �           2606    313813 '   api_definition api_reference2project_fk    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.api_definition
    ADD CONSTRAINT api_reference2project_fk FOREIGN KEY (api_definition2project) REFERENCES leggero.dds_projects(id) MATCH FULL;
 R   ALTER TABLE ONLY leggero.api_definition DROP CONSTRAINT api_reference2project_fk;
       leggero          postgres    false    235    200    3391            �           2606    313818     dds_api_writer api_writer2api_id    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.dds_api_writer
    ADD CONSTRAINT api_writer2api_id FOREIGN KEY (api_writer2api_id) REFERENCES leggero.api_definition(id) MATCH FULL;
 K   ALTER TABLE ONLY leggero.dds_api_writer DROP CONSTRAINT api_writer2api_id;
       leggero          postgres    false    3355    212    200            �           2606    313823 !   dds_api_writer api_writer2version    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.dds_api_writer
    ADD CONSTRAINT api_writer2version FOREIGN KEY (api_writer2version) REFERENCES leggero.dds_project_versions(id) MATCH FULL;
 L   ALTER TABLE ONLY leggero.dds_api_writer DROP CONSTRAINT api_writer2version;
       leggero          postgres    false    3389    234    212            �           2606    313828 $   dds_project_versions dds_projects_fk    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.dds_project_versions
    ADD CONSTRAINT dds_projects_fk FOREIGN KEY (version2project) REFERENCES leggero.dds_projects(id) MATCH FULL;
 O   ALTER TABLE ONLY leggero.dds_project_versions DROP CONSTRAINT dds_projects_fk;
       leggero          admin    false    234    235    3391            �           2606    313833    lg_department_period dept_prd    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.lg_department_period
    ADD CONSTRAINT dept_prd FOREIGN KEY (dept_id) REFERENCES leggero.lg_department(id);
 H   ALTER TABLE ONLY leggero.lg_department_period DROP CONSTRAINT dept_prd;
       leggero          admin    false    259    260    3424            �           2606    313838    lg_department_period emp_prd    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.lg_department_period
    ADD CONSTRAINT emp_prd FOREIGN KEY (emp_id) REFERENCES leggero.lg_employee(id);
 G   ALTER TABLE ONLY leggero.lg_department_period DROP CONSTRAINT emp_prd;
       leggero          admin    false    3438    268    260            �           2606    313843 &   dds_script_definition executor_path_fk    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.dds_script_definition
    ADD CONSTRAINT executor_path_fk FOREIGN KEY (executor_path_id) REFERENCES leggero.dds_script_executors(id) MATCH FULL;
 Q   ALTER TABLE ONLY leggero.dds_script_definition DROP CONSTRAINT executor_path_fk;
       leggero          postgres    false    240    244    3401            �           2606    313848 +   dds_pipe_ins_log fk_activity2api_definition    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.dds_pipe_ins_log
    ADD CONSTRAINT fk_activity2api_definition FOREIGN KEY (activity2api_definition) REFERENCES leggero.api_definition(id) MATCH FULL;
 V   ALTER TABLE ONLY leggero.dds_pipe_ins_log DROP CONSTRAINT fk_activity2api_definition;
       leggero          postgres    false    3355    225    200            �           2606    313853 '   dds_pipe_ins_log fk_activity2api_writer    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.dds_pipe_ins_log
    ADD CONSTRAINT fk_activity2api_writer FOREIGN KEY (activity2api_writer) REFERENCES leggero.dds_api_writer(id) MATCH FULL;
 R   ALTER TABLE ONLY leggero.dds_pipe_ins_log DROP CONSTRAINT fk_activity2api_writer;
       leggero          postgres    false    212    225    3369            �           2606    313858 *   dds_pipe_ins_log fk_activity2report_config    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.dds_pipe_ins_log
    ADD CONSTRAINT fk_activity2report_config FOREIGN KEY (activity2report_config) REFERENCES leggero.report_configurations(id) MATCH FULL;
 U   ALTER TABLE ONLY leggero.dds_pipe_ins_log DROP CONSTRAINT fk_activity2report_config;
       leggero          postgres    false    305    225    3491            �           2606    313863 $   dds_pipe_ins_log fk_activity2version    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.dds_pipe_ins_log
    ADD CONSTRAINT fk_activity2version FOREIGN KEY (activity2version) REFERENCES leggero.dds_project_versions(id) MATCH FULL;
 O   ALTER TABLE ONLY leggero.dds_pipe_ins_log DROP CONSTRAINT fk_activity2version;
       leggero          postgres    false    234    225    3389            �           2606    313868 %   dds_pipe_ins_log fk_activity2write_db    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.dds_pipe_ins_log
    ADD CONSTRAINT fk_activity2write_db FOREIGN KEY (activity2write_db) REFERENCES leggero.write_to_db_configuration(id) MATCH FULL;
 P   ALTER TABLE ONLY leggero.dds_pipe_ins_log DROP CONSTRAINT fk_activity2write_db;
       leggero          postgres    false    3497    225    311            �           2606    313873 /   api_writer_audit fk_api_writer_audit2api_writer    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.api_writer_audit
    ADD CONSTRAINT fk_api_writer_audit2api_writer FOREIGN KEY (api_writer_audit2api_writer) REFERENCES leggero.dds_api_writer(id) MATCH FULL;
 Z   ALTER TABLE ONLY leggero.api_writer_audit DROP CONSTRAINT fk_api_writer_audit2api_writer;
       leggero          postgres    false    202    3369    212            �           2606    313878 2   api_writer_audit fk_api_writer_audit2node_instance    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.api_writer_audit
    ADD CONSTRAINT fk_api_writer_audit2node_instance FOREIGN KEY (api_writer_audit2node_instance) REFERENCES leggero.dds_pipe_ins_log(id) MATCH FULL;
 ]   ALTER TABLE ONLY leggero.api_writer_audit DROP CONSTRAINT fk_api_writer_audit2node_instance;
       leggero          postgres    false    3381    225    202            �           2606    313883 -   api_writer_audit fk_api_writer_audit2pipe_ins    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.api_writer_audit
    ADD CONSTRAINT fk_api_writer_audit2pipe_ins FOREIGN KEY (api_writer_audit2pipe_ins) REFERENCES leggero.dds_pipeline_instance(id) MATCH FULL;
 X   ALTER TABLE ONLY leggero.api_writer_audit DROP CONSTRAINT fk_api_writer_audit2pipe_ins;
       leggero          postgres    false    3387    202    232            �           2606    313888 6   at_email_configuration fk_at_email_config2email_config    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.at_email_configuration
    ADD CONSTRAINT fk_at_email_config2email_config FOREIGN KEY (at2parent_object) REFERENCES leggero.email_configuration(id) MATCH FULL;
 a   ALTER TABLE ONLY leggero.at_email_configuration DROP CONSTRAINT fk_at_email_config2email_config;
       leggero          postgres    false    246    204    3409            �           2606    313893 #   lg_dshbgroup_dashboard fk_dashboard    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.lg_dshbgroup_dashboard
    ADD CONSTRAINT fk_dashboard FOREIGN KEY (dashboard_id) REFERENCES leggero.lg_dashboards(id);
 N   ALTER TABLE ONLY leggero.lg_dshbgroup_dashboard DROP CONSTRAINT fk_dashboard;
       leggero          admin    false    266    3422    257            �           2606    313898 &   lg_user_home_dashboard fk_dashboard_id    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.lg_user_home_dashboard
    ADD CONSTRAINT fk_dashboard_id FOREIGN KEY (dashboard_id) REFERENCES leggero.lg_dashboards(id) MATCH FULL;
 Q   ALTER TABLE ONLY leggero.lg_user_home_dashboard DROP CONSTRAINT fk_dashboard_id;
       leggero          postgres    false    257    3422    292            �           2606    313903 (   lg_dshbgroup_dashboard fk_dashboardgroup    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.lg_dshbgroup_dashboard
    ADD CONSTRAINT fk_dashboardgroup FOREIGN KEY (dshbgroup_id) REFERENCES leggero.lg_dshb_group(id);
 S   ALTER TABLE ONLY leggero.lg_dshbgroup_dashboard DROP CONSTRAINT fk_dashboardgroup;
       leggero          admin    false    266    3428    262            �           2606    313908 $   datasource fk_datasource_connections    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.datasource
    ADD CONSTRAINT fk_datasource_connections FOREIGN KEY (connection_id) REFERENCES leggero.connections(con_id);
 O   ALTER TABLE ONLY leggero.datasource DROP CONSTRAINT fk_datasource_connections;
       leggero          admin    false    3361    209    207            �           2606    313913 2   db_writer_audit fk_db_writer2dds_pipeline_instance    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.db_writer_audit
    ADD CONSTRAINT fk_db_writer2dds_pipeline_instance FOREIGN KEY (db_writer_audit2pipe_ins) REFERENCES leggero.dds_pipeline_instance(id) MATCH FULL;
 ]   ALTER TABLE ONLY leggero.db_writer_audit DROP CONSTRAINT fk_db_writer2dds_pipeline_instance;
       leggero          postgres    false    210    3387    232            �           2606    313918 ,   db_writer_audit fk_db_writer_audit2db_writer    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.db_writer_audit
    ADD CONSTRAINT fk_db_writer_audit2db_writer FOREIGN KEY (db_writer_audit2db_writer) REFERENCES leggero.write_to_db_configuration(id) MATCH FULL;
 W   ALTER TABLE ONLY leggero.db_writer_audit DROP CONSTRAINT fk_db_writer_audit2db_writer;
       leggero          postgres    false    3497    210    311            �           2606    313923 0   db_writer_audit fk_db_writer_audit2node_instance    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.db_writer_audit
    ADD CONSTRAINT fk_db_writer_audit2node_instance FOREIGN KEY (db_writer_audit2node_instance) REFERENCES leggero.dds_pipe_ins_log(id) MATCH FULL;
 [   ALTER TABLE ONLY leggero.db_writer_audit DROP CONSTRAINT fk_db_writer_audit2node_instance;
       leggero          postgres    false    210    3381    225            �           2606    313928    lg_dshb_group_user fk_dshbgroup    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.lg_dshb_group_user
    ADD CONSTRAINT fk_dshbgroup FOREIGN KEY (dshb_group_id) REFERENCES leggero.lg_dshb_group(id);
 J   ALTER TABLE ONLY leggero.lg_dshb_group_user DROP CONSTRAINT fk_dshbgroup;
       leggero          admin    false    264    262    3428            �           2606    313933    lg_dshb_group_user fk_dshbuser    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.lg_dshb_group_user
    ADD CONSTRAINT fk_dshbuser FOREIGN KEY (user_id) REFERENCES leggero.lg_user(id);
 I   ALTER TABLE ONLY leggero.lg_dshb_group_user DROP CONSTRAINT fk_dshbuser;
       leggero          admin    false    290    3469    264            �           2606    313938 2   email_configuration fk_email_configuration2project    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.email_configuration
    ADD CONSTRAINT fk_email_configuration2project FOREIGN KEY (email_configuration2project) REFERENCES leggero.dds_projects(id) MATCH FULL;
 ]   ALTER TABLE ONLY leggero.email_configuration DROP CONSTRAINT fk_email_configuration2project;
       leggero          postgres    false    3391    246    235            �           2606    313943 7   email_read_param_config fk_email_read_conf2email_config    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.email_read_param_config
    ADD CONSTRAINT fk_email_read_conf2email_config FOREIGN KEY (email_read_conf2email_config) REFERENCES leggero.email_configuration(id) MATCH FULL;
 b   ALTER TABLE ONLY leggero.email_read_param_config DROP CONSTRAINT fk_email_read_conf2email_config;
       leggero          postgres    false    3409    246    248            �           2606    313948 &   schedule_instance fk_instance2schedule    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.schedule_instance
    ADD CONSTRAINT fk_instance2schedule FOREIGN KEY (instance2schedule) REFERENCES leggero.run_schedule_rules(id) MATCH FULL;
 Q   ALTER TABLE ONLY leggero.schedule_instance DROP CONSTRAINT fk_instance2schedule;
       leggero          postgres    false    307    309    3493            �           2606    313953 #   lg_columns fk_lg_columns_lg_tables1    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.lg_columns
    ADD CONSTRAINT fk_lg_columns_lg_tables1 FOREIGN KEY (parent_id) REFERENCES leggero.lg_tables(id);
 N   ALTER TABLE ONLY leggero.lg_columns DROP CONSTRAINT fk_lg_columns_lg_tables1;
       leggero          admin    false    253    294    3475            �           2606    313958 ;   lg_rep_dashboard_group_to_user fk_lg_report_dashboard_group    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.lg_rep_dashboard_group_to_user
    ADD CONSTRAINT fk_lg_report_dashboard_group FOREIGN KEY (rep_dashboard_group_id) REFERENCES leggero.lg_report_dashboard_group(id) MATCH FULL;
 f   ALTER TABLE ONLY leggero.lg_rep_dashboard_group_to_user DROP CONSTRAINT fk_lg_report_dashboard_group;
       leggero          postgres    false    286    274    3463            �           2606    313963 "   lg_tables fk_lg_tables_datasource1    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.lg_tables
    ADD CONSTRAINT fk_lg_tables_datasource1 FOREIGN KEY (data_source_id) REFERENCES leggero.datasource(ds_id);
 M   ALTER TABLE ONLY leggero.lg_tables DROP CONSTRAINT fk_lg_tables_datasource1;
       leggero          admin    false    209    294    3365            �           2606    313968 )   lg_rep_dashboard_group_to_user fk_lg_user    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.lg_rep_dashboard_group_to_user
    ADD CONSTRAINT fk_lg_user FOREIGN KEY (user_id) REFERENCES leggero.lg_user(id) MATCH FULL;
 T   ALTER TABLE ONLY leggero.lg_rep_dashboard_group_to_user DROP CONSTRAINT fk_lg_user;
       leggero          postgres    false    290    274    3469            �           2606    313973 &   lg_view_cols fk_lg_view_cols_lg_views1    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.lg_view_cols
    ADD CONSTRAINT fk_lg_view_cols_lg_views1 FOREIGN KEY (parent_id) REFERENCES leggero.lg_views(id);
 Q   ALTER TABLE ONLY leggero.lg_view_cols DROP CONSTRAINT fk_lg_view_cols_lg_views1;
       leggero          admin    false    298    302    3486            �           2606    313978 *   lg_view_tables fk_lg_view_tables_lg_views1    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.lg_view_tables
    ADD CONSTRAINT fk_lg_view_tables_lg_views1 FOREIGN KEY (parent_id) REFERENCES leggero.lg_views(id);
 U   ALTER TABLE ONLY leggero.lg_view_tables DROP CONSTRAINT fk_lg_view_tables_lg_views1;
       leggero          admin    false    302    300    3486            �           2606    313983 .   dds_pipe_ins_log fk_pipe_ins_log2pipe_instance    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.dds_pipe_ins_log
    ADD CONSTRAINT fk_pipe_ins_log2pipe_instance FOREIGN KEY (pipe_ins_log2pipe_instance) REFERENCES leggero.dds_pipeline_instance(id) MATCH FULL;
 Y   ALTER TABLE ONLY leggero.dds_pipe_ins_log DROP CONSTRAINT fk_pipe_ins_log2pipe_instance;
       leggero          postgres    false    232    3387    225            �           2606    313988 3   dds_pipeline_instance fk_pipeline_instance2pipeline    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.dds_pipeline_instance
    ADD CONSTRAINT fk_pipeline_instance2pipeline FOREIGN KEY (pipeline_instance2pipeline) REFERENCES leggero.dds_pipeline(id) MATCH FULL;
 ^   ALTER TABLE ONLY leggero.dds_pipeline_instance DROP CONSTRAINT fk_pipeline_instance2pipeline;
       leggero          postgres    false    232    227    3383            �           2606    313993    lg_composite_widgets fk_qid    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.lg_composite_widgets
    ADD CONSTRAINT fk_qid FOREIGN KEY (query_id) REFERENCES leggero.lg_query(id) MATCH FULL;
 F   ALTER TABLE ONLY leggero.lg_composite_widgets DROP CONSTRAINT fk_qid;
       leggero          postgres    false    255    272    3446            �           2606    313998 1   lg_rep_dashboard_to_dashgroup fk_rep_dashboard_id    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.lg_rep_dashboard_to_dashgroup
    ADD CONSTRAINT fk_rep_dashboard_id FOREIGN KEY (rep_dashboard_id) REFERENCES leggero.lg_report_dashboard(id) MATCH FULL;
 \   ALTER TABLE ONLY leggero.lg_rep_dashboard_to_dashgroup DROP CONSTRAINT fk_rep_dashboard_id;
       leggero          postgres    false    276    3461    284            �           2606    314003    lg_rgroup_user fk_repgroup    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.lg_rgroup_user
    ADD CONSTRAINT fk_repgroup FOREIGN KEY (rgroup_id) REFERENCES leggero.lg_report_group(id);
 E   ALTER TABLE ONLY leggero.lg_rgroup_user DROP CONSTRAINT fk_repgroup;
       leggero          admin    false    278    3452    288            �           2606    314008    lg_rgroup_report fk_report    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.lg_rgroup_report
    ADD CONSTRAINT fk_report FOREIGN KEY (report_id) REFERENCES leggero.lg_reports(id);
 E   ALTER TABLE ONLY leggero.lg_rgroup_report DROP CONSTRAINT fk_report;
       leggero          admin    false    280    3454    282            �           2606    314013 4   lg_rep_dashboard_to_dashgroup fk_report_dashgroup_id    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.lg_rep_dashboard_to_dashgroup
    ADD CONSTRAINT fk_report_dashgroup_id FOREIGN KEY (rep_dashgroup_id) REFERENCES leggero.lg_report_dashboard_group(id) MATCH FULL;
 _   ALTER TABLE ONLY leggero.lg_rep_dashboard_to_dashgroup DROP CONSTRAINT fk_report_dashgroup_id;
       leggero          postgres    false    3463    286    276            �           2606    314018    lg_rgroup_report fk_reportgroup    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.lg_rgroup_report
    ADD CONSTRAINT fk_reportgroup FOREIGN KEY (rgroup_id) REFERENCES leggero.lg_report_group(id);
 J   ALTER TABLE ONLY leggero.lg_rgroup_report DROP CONSTRAINT fk_reportgroup;
       leggero          admin    false    3452    278    282            �           2606    314023    lg_rgroup_user fk_repuser    FK CONSTRAINT     |   ALTER TABLE ONLY leggero.lg_rgroup_user
    ADD CONSTRAINT fk_repuser FOREIGN KEY (user_id) REFERENCES leggero.lg_user(id);
 D   ALTER TABLE ONLY leggero.lg_rgroup_user DROP CONSTRAINT fk_repuser;
       leggero          admin    false    288    290    3469            �           2606    314028 '   run_schedule_rules fk_schedule2pipeline    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.run_schedule_rules
    ADD CONSTRAINT fk_schedule2pipeline FOREIGN KEY (schedule2pipeline) REFERENCES leggero.dds_pipeline(id) MATCH FULL;
 R   ALTER TABLE ONLY leggero.run_schedule_rules DROP CONSTRAINT fk_schedule2pipeline;
       leggero          postgres    false    307    3383    227            �           2606    314033 .   schedule_instance fk_schedule_ins2pipeline_ins    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.schedule_instance
    ADD CONSTRAINT fk_schedule_ins2pipeline_ins FOREIGN KEY (schedule_ins2pipeline_ins) REFERENCES leggero.dds_pipeline_instance(id) MATCH FULL;
 Y   ALTER TABLE ONLY leggero.schedule_instance DROP CONSTRAINT fk_schedule_ins2pipeline_ins;
       leggero          postgres    false    232    3387    309            �           2606    314038 !   lg_user_home_dashboard fk_user_id    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.lg_user_home_dashboard
    ADD CONSTRAINT fk_user_id FOREIGN KEY (user_id) REFERENCES leggero.lg_user(id) MATCH FULL;
 L   ALTER TABLE ONLY leggero.lg_user_home_dashboard DROP CONSTRAINT fk_user_id;
       leggero          postgres    false    292    3469    290            �           2606    314043 %   dds_ftp_definition ftp_def_project_fk    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.dds_ftp_definition
    ADD CONSTRAINT ftp_def_project_fk FOREIGN KEY (ftp_def2project) REFERENCES leggero.dds_projects(id) MATCH FULL;
 P   ALTER TABLE ONLY leggero.dds_ftp_definition DROP CONSTRAINT ftp_def_project_fk;
       leggero          postgres    false    3391    218    235            �           2606    314048    lg_grp_period grp_prd    FK CONSTRAINT     {   ALTER TABLE ONLY leggero.lg_grp_period
    ADD CONSTRAINT grp_prd FOREIGN KEY (grp_id) REFERENCES leggero.lg_user_grp(id);
 @   ALTER TABLE ONLY leggero.lg_grp_period DROP CONSTRAINT grp_prd;
       leggero          admin    false    269    3477    296            �           2606    314053    dds_mapping mapping2version_fk    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.dds_mapping
    ADD CONSTRAINT mapping2version_fk FOREIGN KEY (mapping2dds_version) REFERENCES leggero.dds_project_versions(id) MATCH FULL;
 I   ALTER TABLE ONLY leggero.dds_mapping DROP CONSTRAINT mapping2version_fk;
       leggero          postgres    false    234    3389    222            �           2606    314058     dds_pipeline pipeline2version_fk    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.dds_pipeline
    ADD CONSTRAINT pipeline2version_fk FOREIGN KEY (pipeline2version) REFERENCES leggero.dds_project_versions(id) MATCH FULL;
 K   ALTER TABLE ONLY leggero.dds_pipeline DROP CONSTRAINT pipeline2version_fk;
       leggero          postgres    false    227    234    3389            �           2606    314063    dds_schema project_version_fk    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.dds_schema
    ADD CONSTRAINT project_version_fk FOREIGN KEY (schema2project_version) REFERENCES leggero.dds_project_versions(id) MATCH FULL;
 H   ALTER TABLE ONLY leggero.dds_schema DROP CONSTRAINT project_version_fk;
       leggero          admin    false    238    234    3389            �           2606    314068    lg_aofrmqry queryid    FK CONSTRAINT     x   ALTER TABLE ONLY leggero.lg_aofrmqry
    ADD CONSTRAINT queryid FOREIGN KEY (query_id) REFERENCES leggero.lg_query(id);
 >   ALTER TABLE ONLY leggero.lg_aofrmqry DROP CONSTRAINT queryid;
       leggero          admin    false    251    3446    272            �           2606    314073    lg_reports queryrec    FK CONSTRAINT     x   ALTER TABLE ONLY leggero.lg_reports
    ADD CONSTRAINT queryrec FOREIGN KEY (query_id) REFERENCES leggero.lg_query(id);
 >   ALTER TABLE ONLY leggero.lg_reports DROP CONSTRAINT queryrec;
       leggero          admin    false    3446    272    280            �           2606    314078 .   report_configurations report_configurations_fk    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.report_configurations
    ADD CONSTRAINT report_configurations_fk FOREIGN KEY (report_configurations2version) REFERENCES leggero.dds_project_versions(id) MATCH FULL;
 Y   ALTER TABLE ONLY leggero.report_configurations DROP CONSTRAINT report_configurations_fk;
       leggero          postgres    false    234    3389    305            �           2606    314083 '   dds_script_definition script_project_fk    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.dds_script_definition
    ADD CONSTRAINT script_project_fk FOREIGN KEY (script2project) REFERENCES leggero.dds_projects(id) MATCH FULL;
 R   ALTER TABLE ONLY leggero.dds_script_definition DROP CONSTRAINT script_project_fk;
       leggero          postgres    false    240    235    3391            �           2606    314088 2   dds_script_definition_instance script_to_master_fk    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.dds_script_definition_instance
    ADD CONSTRAINT script_to_master_fk FOREIGN KEY (script2master) REFERENCES leggero.dds_script_definition(id) MATCH FULL;
 ]   ALTER TABLE ONLY leggero.dds_script_definition_instance DROP CONSTRAINT script_to_master_fk;
       leggero          postgres    false    242    240    3395            �           2606    314093    lg_grp_period user_prd    FK CONSTRAINT     y   ALTER TABLE ONLY leggero.lg_grp_period
    ADD CONSTRAINT user_prd FOREIGN KEY (user_id) REFERENCES leggero.lg_user(id);
 A   ALTER TABLE ONLY leggero.lg_grp_period DROP CONSTRAINT user_prd;
       leggero          admin    false    269    290    3469            �           2606    314098 (   dds_custom_functions version_function_fk    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.dds_custom_functions
    ADD CONSTRAINT version_function_fk FOREIGN KEY (function2version) REFERENCES leggero.dds_project_versions(id) MATCH FULL;
 S   ALTER TABLE ONLY leggero.dds_custom_functions DROP CONSTRAINT version_function_fk;
       leggero          admin    false    3389    214    234            �           2606    314103 (   dds_filter_functions version_function_fk    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.dds_filter_functions
    ADD CONSTRAINT version_function_fk FOREIGN KEY (function2version) REFERENCES leggero.dds_project_versions(id) MATCH FULL;
 S   ALTER TABLE ONLY leggero.dds_filter_functions DROP CONSTRAINT version_function_fk;
       leggero          admin    false    216    234    3389            �           2606    314108 &   dds_global_imports version_function_fk    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.dds_global_imports
    ADD CONSTRAINT version_function_fk FOREIGN KEY (function2version) REFERENCES leggero.dds_project_versions(id) MATCH FULL;
 Q   ALTER TABLE ONLY leggero.dds_global_imports DROP CONSTRAINT version_function_fk;
       leggero          admin    false    220    234    3389            �           2606    314113    lg_vinsights viqueryrec    FK CONSTRAINT     |   ALTER TABLE ONLY leggero.lg_vinsights
    ADD CONSTRAINT viqueryrec FOREIGN KEY (query_id) REFERENCES leggero.lg_query(id);
 B   ALTER TABLE ONLY leggero.lg_vinsights DROP CONSTRAINT viqueryrec;
       leggero          admin    false    304    272    3446            �           2606    314118 4   write_to_db_configuration write_db_config2version_fk    FK CONSTRAINT     �   ALTER TABLE ONLY leggero.write_to_db_configuration
    ADD CONSTRAINT write_db_config2version_fk FOREIGN KEY (write_db_config2version) REFERENCES leggero.dds_project_versions(id) MATCH FULL;
 _   ALTER TABLE ONLY leggero.write_to_db_configuration DROP CONSTRAINT write_db_config2version_fk;
       leggero          postgres    false    311    234    3389            s      x������ � �      u      x������ � �      w      x������ � �      y      x������ � �      |      x������ � �      ~      x������ � �            x������ � �      �      x������ � �      �   T   x�3�,H,J-ɏ�E���y%�E�i�e)�E�)�i
x�54�b�� (YZ�����[ZR����Y]���i�Y����� '�$      �      x������ � �      �      x������ � �      �      x������ � �      �   &  x��[O�0ǟ�OQ�y4-�M�a�����:�Oۀo����g'i��*�:��f�c�����m�5z�Ϥ����*� ��������FM�T*����s�����R`�Xp?���j�{��Ng�s�	��{O�c)�;���^�X���K��Ua5l�x;/�=D�{(N c�?���=��Xf��e�ab��D
A����w��ʐ��%��tw�~�d�ȼ⥊�h�c]�8�HM���?�I��ȁ�7Wu�'��S5!MpG��R��B�B&%S'�/�j���"g�H��4��2#�o+N�}e\�K���P������}���D����f
���=�,���݊}S��t'�4�����m����+&�-�����,秐+�
����W��@0�ko�R���:�p��7�h���'.�-ܯ�?H�@�����Ǩ?"g��`�����V-U)�j����{�AoxO�D��G����z��zJ�|���zfU�˼�A]W�Iz�h���M��4n|��;u1�yp��N���7��˒��v����f֚      �      x������ � �      �      x������ � �      �   �  x��[[o�:~V~��}��;�[���=E��<�9d�q�Ȣ���d����%˴�{�8�Er>�3����&�mx��ӌo?yI��]������b���G�|�].�/�o�տ��ԙ����X�g�|dYdòg�<�n�u���8��Q��S��E��a��Ł�S�~�Ӿs!(cF�<��<v��X��a�{��-H�u���iHڮ#��; ����0RQ0Ƥ�*����U��o�0�շ*�2�)��c��^t�M����r\���ֻ!5� ά��qN�
5���9#"�p��q��҄5i��m��j�l푆r,s�)�W� ]p�36�p�㻐�B@���{6�.۹�|[Zz�5k�d�@c2g���hB���=; M�T�bFn݀"���d5�iԹ/x�~�A������H�,���9Ͽ\��]��@�%!�(ޏ3��ɜ5 2g���D�� �>QCA�����P@�U$�5��s�R9�]?���=��<��o��}�'v�a�M|���{����Yٱ6��T��PN����j()uB18�d~}WE���-`���)`��撖�<j!jp�"M�QV���"�s?qg0�� �����/�'Ld!�
�Ʊ�M�:�Թ�f�ė0aQ��8ͼI�*܄j�PW� g�uk��<  ��%H,�l 5�5�in��E6 `�=�
�<�1s�e��C��a���L}@aQn�4B-�f�q�:2MH�DV�X�I��P}�v�P/ybEֹ�/�Z�Y�uPJ�S���8��Y)���v�[i�*�V�vӟat���pH�t��ù^*�.�����	[1���W�nB(��z��m�������ԋI(�܈ś��&;��+o�D��95!R,ud�gP��{Ae��&:tP���!�:�^�X����Պ5r�0���2���	��&���W/R���%��6���r��S��sS�x�n����y�B�7�'=���w�+�U?��\�I�c�4�4m�~�_ |���8c�e�	�п��ni#�8�C�GL�cq�m�ౚO�&TT�<�q'a�P�b2�E)
^Ł�6y� ���KMK?�����|Hnyl��Ǔ=c�:�ӫI�\K�ߍfw��p�K)�6Lkb8��R���-_����i�'��ՑMUokm��kk�ً��0���F5�a(�Ư��O��g�[a���:�YN*�jO�����й����YB4�������/7v΃��@KY���(ɕK�Aɩ#W�B�rXJ�-;bJ@Z�|���$��aI؎�f�*/�rhA��T{e�C �+HD�%����k.j����g�Dn���ç��ʸ+��ֺ�OpJ+�B�Ӈ����,S���Œ�ۃc�:�{�]�C���7=ۄf(�7�rw�B���"t��a�=A ?UG6}r����������4b�����H�'h1�H8(8v.c"��Ά������a��U-.  ;W~I�y�Z�,b�4�	��r�<�ߓX��ņH�"OC��,�"��%�y���H�������P���~��O�k/��RǸ�+�6�#�JU���P����K�nq�\aV��.(g�˲���H�>���8�.enM�h�%.��6��ԾឥE�C��	���W���\�������,R>,�+@�s$k\�Ģ�U�x��O	���d@A�H>����Xu������� ;��s�v�P�Exf��ˮ�f�P׸��&�˵���
[D�q��:P�K,[B�W^\A)��&6����F�6�����r,j1�	)}�1��q���<��G/�Y��6(#�h@`b����puc�P�F�R��_�8f�;+�"���E���N6�	��.�B'���fHͰά`T��T4d��1e��<>�vR��	�T��tF���J��s�v�ĳ~yTu�|.��y��"��P��	��@i�4�M�2����u�cX���r�-�:S�ݿ<�̞y�Y�W	Xh��*�J �aU�j+���Oݎ��(���[Q]kA=5��������j� ����6�����J��pg��M3*m�;��lJ�s�ݬ���ڳ1��,����e���ox^%��h8�-s���?^Z�Ӈ�5���K�9��Ow"<ҹ�Z�L+qT�L>��]gꨃ�fv����	G#c���%�l����4]S}�d{[�'�:P�Mj�l�0���0��`�5�SG��g�Rޣ�<sM�4	�����{�8`�w6�;i>a�ua���o��T����^f����VW��ߡ��v�[F�r4��{��Q�!�[������ �Gc�e��0z}a!Ce��@:���C&ȯ�V���.?�W��W�+��'6��bh�2��y- ����kl�5^�y���k���������s�+�o�R_�I�2UV�^[�_>��{�����ߟ��F�_ڂ�9νƷ����͚�O���ԄI�]��>�ʇ�^e�
G�rt��/v��j\P'�<ڌI�i�{���Ͼ&���x�=��A�k#s��V�`}�لo���,�h�_,��Κ	~��r�?�w|o+�H���B[]^�6��J�P3�g�&�ue���y�;�Ǹ|鏙��I��e(g�o/2�N ��˭F�)��~H���e���e�~��og���	x����/���95�}�����faϵ�8�!�����Z�tF�= մ��z����_5(Y��+�}�
��V���:�Ú;z���M���w\���׌��E��Թ��&t����n��==���7�38���i_kc��mg[̮���h��^�� Xb#x���%U���d��i%�ٰ:+]�`(�	��K�Q��������l��}�C29�Wp쓍czj�)�Ƹ2��xU���NY��[Y�ƃ�0�TY'
�N��跿��<�      �      x������ � �      �   �   x�͐��0���)����<s&> �RYU�d$j|w@=�Om�����Ŭ�X�[hJ�hlA�e);���s'Ua�*�bO
}�N�Q��nX�B�86P;2B)+8`����3��L�c,�|@~�"ڈ_�9���t<�DByS����,����MO����^:׻/��:��׮;M��d��=��ܿ=�Ap�n      �   �   x���AO�0��ۧx���X6<y+�O&ͳ�:������3�aċ���߾����4�LN�Bf��\����/D9��E�����Gp�ɸ���q�nT��r���p��+ܐ5<?��Eϵ2�M ǵ�Rc@�����28���\��"��5)��N��xG`_�(��a���i�My0LxFj]��;�Ԥ|_�<w��l�?��K��g���i�O��"i/�t��m��(      �      x��[oI����_!�1+'���\�j��R�<�3�9 X]&JJrç��0H�L2#LJ�;2>��AyےB����k�o+�O���$��觨�)NO㺟��8	�,+��$}�$'_{��^=���rt1�����������MEY��m4������ů����ޏ�&�G�������b�_����F�瓋����?_�_^�*Ǘ����j4+���.�w�����~��>������r|�>�����hV�݌�û�T}���-���3]�}���|r����|����ڻ�r3_������ٿ�͖N�jת�9�f����U;����r|��������]�zx{w��^�����W���xz��������~~�������=�\ܟ����t���zxy���|ts7�\�>��n8�[������sMGW����~�r;>�}�����6�]1�3]1�'�w�_f���Ki���K�O�at9��4���m�����?&ӿ6+o&���,W���3-
7��/�Q������v2]��~�N�MO_L.�|��7���7?����-~J��������������{f?ջ�۞�f��a��L�����eMG�G��_i6+�ߎ./�Y%��N�}|1�����}�7�z1���ލf{�z7���ۧ�����Ǫ���>}�c:�h���'W7�w�٧�}x1�N������>.�˿;������Z��%88�4:�k�����zy��u\��i�uV�:.��E�ϋ0.����?�8Qx�S�ʉ�ENg޿z����h����/{�~�?�����~�^�����`�_O��]+1,J�a�~%�k>;&݁iu xĉ)��i�uV�:�����R�8�q���!��C�?���%��7�����ݨ������ܨC�r�<��������O�<F,?d0_H�]ٿw���~7]|���X�:qx��Y�I�Ե:���j�R������7oO8�ͪ˥�.6fc1�O���?�?f�+��4^��?��������Ɓ��GiX�U���@Yr����J�%J�(9P>�@��6��28W���ϓ�<�n_VW��II��:�VqH�R���#.G\���qVо���!/Eb��?ko_m�g�$�Gi?��"K��M��[�9�*UNޜ�9ys�������Z��d7�^<0|8���iW��,��.�����>g�����Ƣʨ>|3����������]ΞN?�-�����R��ui�Vm[�}�y��W�����F��Ʊ塰��g�Ӈ[�lv3]��������/�����Ow�T5ul|�:6��bty��c��<#�>���/Nݯ�gw���6�~y(?��]���<��<yiTۇ���}�����n��w�������������������fv[ٌ�~���?��:3�#g�����p��.�7�B��8��>��\��\���O4�§��C���ŉ|�rXjCV���B0�6o��l0\���U�"V��XE.`w�|f,�;t{����:l���uXڧ�uX>�N./�W�jx-�������z�Q�F�Z���a�>�O��\���ڝ,�����a���n��#v봩���4Z�`�SԜ�Z���2�j/�qa��f,h(���7����;J�6�c��4�x�{08���5/)�+C� �?Nͷ��Yc|�T�#g?U۟�5Q�T�U%�C��(Q���v��7ɉPY�{�p�~O��Y`��Y�W���q#�2."(Ȗ2dK�����m�]-5lK��+H�G
8��+=�Y��i?M�q&E�&jfBAn	hΩRE�A�A�A�A�qN�@p ��;I�I�X�O����(TOӓ8AR�JOBOBOBOBO�MGDGDG�7ɕ�(K�4��\��K�#gY�T��������ҟ�ട����e��T��ѯ	8]S�J�F�F�F�F�F��H�H���ѕ�uͶ,N4�q܏�0��,S��ӂ�V@+B�*�-�-�-�-ͭ�-ӂ�[+������[B�u��v��qCH�i�uQ��wZ!hڨRE@@@@@@@@@�0��oq�xՍ;�9%�IXdqQ�JNI�S4�T�"� � � � �� ��3���:��w����~�eeu��ɜfR�џ*U�I�I�I�I�I�I�y���
h�i�i����D����
�<O���-*i��ET��h�h�h�h�h�h�h�h�h�hw)O�\N���"Sc��:K�y&�F��XR��T�T�T�T�T�T�T�T�T�T�%�bv��W�c�p�e0�����@@��!�w�a�!���(	�8�b%�d�B�9^_����-���ë=�]1<�-~◳��OK���]_ݧkՖ.��.��♱��?��V��}�Ca����O����t5Z��m}��/��w���i
��:���6�������[��R9}�x��%46�����Ն���fC����t���k\;����9t����ͧ�alO}���՞*�nUQ�Q�Q�Q�Q�Q�{������������������i���RM��J��V�bB��s�T�{�{�{�{�{�{�{�{�{�{�{�{�{�{�.�T�$	����D�=�)�ID�*M"��D4{Å��:��sX~�k㲵���oE­�T��v�v�v�v���nnnnnG{	���=��7^u��0�]܎����������Q�v������v�vR�o{Wl��9a����%� ���]i�T�Q�;�q2�J�I'?�(�(�(�(���Q�Q�Q��4�����{�xՍ;ðw��~��i�%q���?JN��_?
?*���ܻ��=���������K��CSn�.�\\��f9�Q����1��������]w�a\;\;\;\;��7^u��0�]7\���a��e�L��NN��_��.b��z�!�#�S��d�d�d�d����d�d�d�d�d�d�d�d�d�d������Q�U\�s�&E��ӣ�WE�G��h��y�'�s7ּ�����@�*������ώ��,�,�,�,�,�����������}�U7���u�YH�Q���Ί,�� 9΂�ݿ*��B�� �l{����+����w�s��	�b�T�t������������������nS�������ƫn����S��2L���2��80rzt��8080��b���a��N5�@�;q�J�I�-\ \ \ \�Μ�q�p�p�p�p�p�p�p�p�t.P�O�,�,��T���������@�{��/����[�q�wh�D��Ρ�c�c�c�ct�c�c�c��;q�p�p�p��{�xՍ;ðw�p��~��YT�Qy�>�#�19=�U�1ܱ wwwly��٠S����K���M��x�6gJ�T�tf�I�I�I�I��I�I�I�|���������赓G�(�<J�D9�1N��ݿ*N"Nb��������h�QZ��4ki�~px��;�sڥJ�I�''''}"''g��[w<N<N<Ξ~���qg��+g��Q��%�'x�rzt��x�x�'�e��>)�e�Ъ��eݾ�q]׌p��J�I��+�+�+�+�+�+�+�k��[y\W\W\מ~���qg���k܏��J��Ȕ���������������b�$\W\�uo������s�K�7.,���&��T�������������K��Wr��������w�a���I�Gy���p�����Uq�q��a��a�#���F{{zu5��{�Q���1n��8��T���V�V�V�V�V�V��­ƭ�K�W���ƭƭ�����w�a��V'���(˳���ZN��_��:���=?/,�:����i���w�x�x�[���Ոo~�v��*�}�������������������D�U#������{��o��Ɲaػ���YfuT���|s9=�U|s|� ����\F��o�o��s|0_X�=q�{��^�)p�����Q��OGGGGGG_}�>��_R��:	�>�>�~O���Wݸ3{�G?�'IXgi+��q�����Uq�q�}}}}m"�>�~cOHp�o�    ��pqL$"V��XE&`_ٟ�E$��	�}���E��u�݃@w[�r9����A��>UR.�\H��r!�B�E})R.~ɗ�j��\H��r�����w�aﺑr��IFi���KJ�EN��_��)�����)۝3!B6r�TB6�l{���a^�l�V�؝B��>D}�D}t�j�<�:�D�*D��>U�@d���"�ME�,��Z�"D�,Y �@d�ZY��
���\d�2�@rzt��d��d���"D�J�,Y �@d�u5�z�;�L�$G3I������<4+�T���T"�DR��I�n�$�Vׂ�I%�J$�H*�T"���T*�YFug�J*�$�����UI*�T
H*�T�7�t��=ӮND�NhJR�Lh��TcO�2����)BS��M���T�yP&Cu8i5�*�}�d��P��"CE���J0�յ CE��*2Td��Pmf��r��*�:�U��$C%�G��J��U@��*2Td�d5�d��P5�*�*�P����j����^��]J��LY�3e�[^�?��vɟQ�J����3�g��&�3Tt�*6�3�gn���j���ȟ�?ېc�͟U�UՕʟU������Uɟ�?ȟ�?#F����������ƞ fX�3�g��D��Z��O�����9��-I�m~���R%G:�t��_�t�}��t�8��~�v�q��H�m�1ަ��~\�eQ�U��q5�89=�U�q���q��HǑ�#'�a&G:��'H�VA:NT�t�8��8)�+)=Rz������߬d�6�]�{T���#�Gv����Iv¾@v��[V��> �=�{d�r��w�aﺒ���0���JO�g9�YUP��_��ٽ����=��9��*�5Im"�5k�=!!�F҂��!�$אӃR��O����$H�<PE��_���z��$z��o��ƝaػN$f���a]�UQ��S����UI�<H�< y@�@F�H��AcOHHȘ�#e29rǝxAb�pB�;U��TIl�� �Ab����Q$6Hl�%������ �Ab����ƫn����Fb#�gE�uT&'�2%�!�G��Jb��F@b��Ć�Ι��$�s��]1w��C�<R�σ�= H#A@ H#7H�/�2��_:�/��N���S��7��j8}�$$ɯ{��3���g��yl5��H7�]b�T�#%FJ����I�3̾E���[F��.1RdLb�f�ǣi���8,�8�*5��"F*�G��J��i@�������~�~x�61 �(�S%�(9�F��4ɏK���8�\@�L��>Ur�"�E�� A.B}�r~	^��M�"�E�������w�a�:����~T�YU�\D���ӣ�W%A." A.�\�m"�r�=!!�'�OD�� #BF����$��XP�RݧJ��,	Y�$dIȒ��"KB��/��_��,	Y�$=��7^u��0�]7�$y?��"ͳ�PY��,��ݿ*Y�$Y�$dIȒ�hɒ�%i�	�$�UXʒ�;��S�]B��\����C��p�JU��T�ߐ�!C�����Q�o���%���j��!C�����ƫn����J�&�ê��j��)���������!���:c�s��9z�iW'�s'�$�a&�D��'H"VA�$���x�l���u��D2�d��dV`R7>��̩��Hxm~�$��R%�E�	��_��:�}���	/�k�b^$�Hxm�1�&�����a�fq�~[W�o�ԣ�W%�E�+ �E�	/^�f^$�{���a$�Hx���o�v��:,�S)�����xϒ$�_
P�p�?���mL�p��%aH�*	C�$I���$�I��$I�e���V�0$aH��,�x�0L�~\�iGi��1	C9=�U�$�$I�0$a(�a&aH°�'HVA��zr��!	C���aG��v4>kHAn~�� �R%I
�$)��_�$^�}/�$)H�LR�� IA��R�YQ��JAf'�3��vq�!�P�*��|�|�|s�L�a��7�N}�N7�)��7���;��c�����`�*���>�a�6�5��y�Ɵ�C O"���'�'�'�'�'�'�<>���E@[<B[���`�9ݙ���!DA�*!
B�(``vv1)
K�<��Z��`D���� c����4����(�$��J109������U��#��#%FJ��)�;1R�1Rb��H��#%F��z�7>1Rb�F�)1Rb��H�R%FJ��)1�G}Mb��a��(b��H�2��u���"c#5K=~�H�2̋2^�R/N��~{��ه���lA�/˅�o/�<�� �[m�����û���w�g����o�=̋ׯ^������߽~���n�a��o�χW��W^=}6o���������x��e��ݛ�X|��w�~����������E���_���Rz���ٻ����{���?N�1�g�?��>���o_���������.�o�2xR?��kw������C;�Y�s�e l���6�t���^���%�O��6a|�G����	�����'������ �o=�L�0>a|\��}��'��
��	��_ߜ��Rb��'�O�0~g�8��0���kA#�0>a|dL����a���U��˼,�\��˓��7�wɬT�u�J��m�t��~�����M���Z�1+�u��.�g����;�}�N~����������CU�����5-�����Gy��|�|��І�@�������Ej����h�	��*`>�g�a>`>`>0K�����
000��*U!�����Gg�8��0��յ��������@Ƅ���h2E?)�Y�YT%�b>*����D�����c���;/~t�l�r������������j� �����8=888�O 88��'�S� N��NNN����7>p
p�* � � ��oN��T�6�)�)�)�)����6ÀSV�8#
8888eNI�~�Ye���888%�Ū�>NNq
N	�G(q���v��ex'�Rm���e�e�x߁���ˀˀ���R�ˀ�4���a�2�1ppp|��}�ˀ˨��������JU�a....�+�o3\fu-�e0��e�e�1�e�eZ�L��Y^�Ey�>�"ppp�D���\\\ƵV���o��;�h <�'}��ޞ < <{��Axp-@x@x@x�}@x$�7 < < < < < <x��z��������JU�a�����+�o3�gu-@x0�@x@x�1Ax@xZO��QY�Q�����%�Ū�>���q�o��,�ػ�&޸�;�@E��}����@E@E{�
���Q�������}<��$�I@E@E@E@E@E@E���z��PPP���*�JU�aTTTT�+�o3�hu-쇣���7� #�_���,����8�:M�9T� �$�X5��@E@E@E]ꛛ7�!���a�q=��q���`���S�/��Y�	�i������/>��ScO <V�d$xxx")�o|�'�'U xxxZߜ OT�
1l � � � �:c��m�<��������ї ���	�d�z|��~��q�e�ߢ�<<<�$�X5�� O O�k��i���߷\=��>�j��]ݚ;���W�q|��N>�W�W{����p�������|q�����{�ʰ
�+�X������}�_�_���������JU�a~~~~�+�o3�ju-$Ǹ�������+dL�+���~��a�YR*�*���BIt�j���������,I��dEH%��_OiA�����>0'._��s00��9`0�/`0`0`0_<8`0`�ƞ 3��:dF��{���`�`� ��9���Rb� ����uƊ��[]ɡ.`0`��/�,�����$	�4-�9�����$�X5���`�`�`�`�����	��C�A?�H�\��M�'A_���!�    ���L 5|9 5 5 5_�A 5 �ƞ R3�H�:����F��{��@j@j� �����9�ԨRb� ����uƊ��R[]�a3 5 ��/HH�,���eUXEq�
R+�ԀԀ�P]��c 5 5 5 ���^Bj��S��hŎ�ɵ~p;#�9N��T[gV�9��=N��sx��s�s�s���6�  �8888���888���HI��s�s�s�s�s�sT�J���9�9�9���Xq~�a�s�k!9 88w�% �!cΙ�����Ua��y1�J�9�9�9�D���pppp�;����%�m�W�!	�C��v!�֏tg����ٗj�@�շǱ�#����(�����~������QW����1K��	�������������R�Rm6P}P}P}P}����6à�V�Br:����K��CƄ�3K=~Q}����:/�WA�A�A��$�X5��P}P}P}P}���O�!22�p���
�ﵝ}$�!�y_��#>�!�a g��
gg(�E�3��	=���?�!�!�!�ᣮ�!�!��c�"%�������R�*��2l����;c��m������ �!��ї g��	gh�z���8L�2���p�p�p�(�.V��1�!�!�!�awt8Co3�p�����=~�z��w�!i:|��ZxHx� RT+	ig	zI�D<$<$<$<䣮<$<$<�c�"%H�CvUȆ��������Jսj˰�������������s���G_<$2&<�Y����iVE�I����!�!�!Q]��cxHxHxH�xH벁��D� ��-@f�r,�2�^;�o�L� _���>>3��Ē�τ��Y�g�Y����>!�	�	�	�����	�	����H	6�]յ�3�3�3�3�Ru��2l�3�3�3�3;c��m��g����#|&|�ї ���	�i�z��3�*��:J�g����(�.V��1|&|&|&|��V��|��!Z�L�!V��4]�Du�c�2 9J{�K�մA�B����吣���z^�Q;K����g7 G�5ݐ��U@�B���9
9J�j�r��Z7�(�(�(�(U��U[��(�(�(�hg�8��0��յ����=� G�1!G�R�O�h�~�g�I>'G�Q�Q�Q�D���rrrr���D�r��-��������V��٩[���<�Rm��p�p�\+V>\+\������$�����Vy� \�qp��"�V�V�V'a\kWp�V�V�V�V�Tݫ��V�V�V���Xq~�ap��k!9
�
�z�%��"cµ����ֲ�a�Eu������!�Ū�>kkkku4�*Q� k�6C��@�5p-�k�k�
��v�NA���֗j���� n� �܊�
 n�,A�X`y�/V ��Gnnnn]O� �]U�nnnn�Ru��2l nnnn;c��m�ܮ����*�-��ї p��	pk�z�n�:��8�JE�f���(�.V��1�-�-�-ĭ�V��ĭ�!Z�[B���[QZ)�M�Np���J��wj=��4ܾT[m8,0,p L�X��lg	d�4,�x�>e	�z�.��RL��{Ֆa�+�o3xu-$Gja�a���X`dLX`�����a�FEY+8���FIt�j��a�a�a�a�ͰJ.`����;b�����u<g����u��n��T����|��(e(� J�`�2��(}J��$,�9!(e����
��<�	JJJ��x_ ��U�JJJJ�*U��-�JJJJ�3V��f���ZH�B)C)}	P�ȘP�f��'J��GIX�E�U�R.������Q]��c(e(e(e(eG3��(eoC�P��X����EDi��XO{�J�1�;^w����4"�/Ֆt??�O�������O�Y���>�?-^zB��.��O�O�O�O;<৻���O�O�O�OS��^�e��O�O�O�OwƊ����^]�1d�i��/~~�,���O'IX�yZ��.���Q]��c�i�i�i�iG3���ioC����X�������(n(n)��٩�Av#��Rm�*�ݐ�d7a���ݐݨb�@v#JAvCv#G!G�.GAvCvCv;� ����CvCvCvCvS��^�e�@vCvCvCvwƊ����^]�i�n��/���1T�n�dw�IT�Q���
���%�Ū�>����_��ݺ��K��J�M ˽���;��,���$ɫ�G ��%��AS�ܩ"B�#��Rm	<P�P��9�o�9(s��9
U�	e��2���M�M�Ҧ�̡̡̝�gP�]�ܡ̡̡̡̩Ru��2l�̡̡̡�;c��m�A�����4�9��ї e��y�L*��L�<�ªH�(U�yeee���b�xC�C�C�C��:e(sGu(so3�P�dh����$I���II^K����;hw�W���=�t�ݝ���0�0�Ta�a�a�ׇxo�C����#�����5�P�)4x���ʙl�ޅ�h �U!�*U��-��3V��f��ZH�r����}	0�Ș�O���Kd��~��Q�Er�>��)�Ū�>����o��@��
'@�ކx����ۏI���#�����!�b�3����'��9�{*�Q�'F���o�,�>2�/Ֆ8����J�F��__9�"�>�^�	e���.������@�A�A�]ȶ �]��A�A�A�A��Ru��2l@�A�A�A�;c��m��诮��9�>��ї ���y��*��LD?)�2-�*�#�1�>�>�>R��U�}�����j�A�N@����;�ѷ�$ʫ�G$Ey=G��D��"2*@�ҽtOgݳR��
�:*@��w
�@��ڒ� � ��d���] ��r�O�=6�P�>��>QQe����}`����HI��h� 0@�T��Wm6`�  �+�o3��k!9� }	@�<~��2dU��yV��	 � �D����`� Z�2N �m���h `?&I�W�H��2@�Hqw2�2н	u�%�[B���=A��2�o���5��}���E�0� `��.oTa����i��(��'�u����Y4Q�*�(Z�|-���o૔�x�0ހ�T��Wm6�7`��o�+�o3���k!9��x�}	�7@�<~֕��dQ?�¤.�:��7Ho�x� %�X5�ǌ7`��o�j�o�p�xoC��7p D�x�1I���{DR���D�F��f2fA�Fֽuo+ݻC�$�1fAS������K�%{2|���țy�Y3|a}-��_@�m<���_����נPlQJQJ��zj9`�BW~�/0|��_�Jսj˰a�������Xq~�a_X]���p�%0|��	X�/���FaZ�i\·/d_`���]��c�/0|��_h��_pT8a���!^�/8�e����$Q^�=")���"�D���e��d�{O�ޚ�w�����UvJ���@~���e�h�����Q���rdmFC�*7�P��LFC�W�ѓ�+d���踮�d��o|FCtQ�g4�!�h�Tݫ�FC0�������h�յ�L80��G_�!�1���e4�������̳$M�!rFC0��H�.V��1�!�hFC�Ze�h�O�+��8뺉��D��ަ��M�@����s�d�����,1�)�4�i�jH������=�{k��a�7J m6E�ٿ�"U��K�%3��Q�*H�y��3�b}-�܌�@dn<��â��/r#/�̐��u�u]�u�xk�������
FU0��QT��Wm6��`T�*U�+�o3�Q�k!x`T�*��FU c?&˨�
U��"���������Q��`TR��U�}̨
FU0��Q�V�Q   ��k2�����"�(1+��3�2�3+�~P�0���ffV�jB�]M�2+Cw2н�uoM�;L�F	���6�ɝ��3��}��DkFg0:#`tiAoFg���ћ�h΍'�ux���5o�f��j3*/*�k*/�s���]4���Fg0:�*U��-Æ���`t�3:c��m�1:cu-$���`t�ї��d��f�q@�〣3�4,�$)��茒���`tR��U�}��Fg0:���V�<:�|tyi�Gdv�;DkW���6G��r��T%M��G$����A��TwWc���Нt�i�[S�ӽQ�fw���N��Q��T[":�<�0ʃ��7�<��B��($���:L�(�8�}9����5ї����(�.z��`��<�A��{Ֆa�(Fy0ʃQ����6�屺�qFy0���K`�2��C���8��q�QY�u��|�G�(Fy0�)�Ū�>f��<��(�V��(Fy�c��]1��b����Ă�%H�r3Mā(5�D�e	t��I�n��,'X�դ0�Dt'�{Z��Խ�to���i"���~�}�x$|_�-a��"�	/B��W��"�k!G�g��Y\�&m�e��xM5ھ���
�
�
L._��g�HMƋ0^��"��Jսj˰a��E/�x��Xq~�a�Y]Ɉ�E/r�%0^���ZƋP�8�x���a]$iT�ǋԌa��E�]��cƋ0^��"�i�ʌa��1f���E/�x��(5�Et?n�/B��`�s֐ۑe��(�����{��^mA����O�|���Ɵ0�$`�	�Oo\#Ɵ���߀�'Rd{	��} ��'�5{�r��j9*5*�c*5܀�����.z	�?a�	�OB��{Ֆa��Ɵ0���'����6����Ɵ0���K`�	2��ö�?9��q��'i�I���G�?a�	�O�]��cƟ0���'�?i�ʌ?a��1f���O����(5�Ot?n�B��`�k��if�0�E�,�oܚ;m8ƴ`��Rm$�iaLK����޸[�iY_9�F����;K������"�[@շ�S�꣦��;���7����i����ƴ0��1-T��Wm6�iaLcZ��+�o3�1-�k!uaLcZ��ƴ c?�˘�
�R��2,�.�SZ⓯�R�ƕ���aT'E��d��h�M��Ⱞ�".O�ٿIO���m���Dus�������^���o�C���_/��n��Ե�=A��ڒ/��������t<�����d�JL'����R74���=�N>��U��_6�����/��?g���e��A�x����"w��~�V5��c%��~?�/g����ߦ���E�=�V~�3�߯��?������/^̾؟���I����oԝq�xb�>�uu����qsz6�.�����_�?�}��a��>��^��]����o�GM�`�0�(�1�H�(�=����<��Y?��4����?p��7�N���U�4�<M����|�����,U�<dy�n>d�<��qX%qUf�h��*P�2��O����L'�����?��|�_�'�n�O����8���C��OR�t�7I$?��_��"���G�'?U��<�y��z�Ͽ��j�c[:ث����yIժ=I�8���K��%E��/)^R�jO�ӭ��@�|x������*���l�c��ޯ��������K���]|��_$ڗI���$~���������z���:�WI�T��>{������z      �      x������ � �      �      x������ � �      �      x������ � �      �      x������ � �      �      x������ � �      �      x������ � �      �      x������ � �      �   o  x��]mo�8�l�
!w8�� �'��ri��f7���E�W����ȒN/ι���#�7�%J�l*Q�m�9����P|F�z�=t�������#��S>�ݣ�#̡A~mX��L��3��[Ç�gy����믎����h�6&�f������-a9��_��v�ǅc��>L^����r����Gk]��P��Loil�+�����}�lfa� (7[�f�ZP���e�W���]�A6y\��$_@�
���0�vz)߆���0M?�Yb*߿~�yd�f��w��ŗHס9K?�>X����i4��R�<An�cH~jfgSP��r�+A�se�A�\GU�6�Y+����F?F��prrq~����p�v�<��Հ+��X�?�Sm	WP���4u�h�<����ǘ]�G%�QW/���R�`#/2���C�_%�!���vv�*W�AM��y�ϯp������a��cP���J���~󖄽-��R�Y�N]��4(����rWQA�v]�d㰠ܱ�]ZO�!��B~|���ʿé�x�0K_�'?�e_�ol���ϋ~��G�F���4]�r�� k��7�9���X:Ą���� �PS>��݂�]R8F1��B�F�|�I%���`mIM��8�3�'�xU#�f�+�t��f�p�:x`j�P���!E�?���l���BSj��;ǒ? ꅂێ5sH)N�c���2�7@9�S�L�W���Vkp�%���1��Kg�[<8B{h��|m�sE��~���UQ���?��؂ե@�ٳ�	�+L�K������<�!���$�/���`��zxQA~ Ӗ�������O8Þ�)tǉ�vX�CY����WZ�j�|�i>�!�Z��hIY.)��s���ttgy��Mwz�S)vT
������k 4|��@l��1��2l\�C��E5��K�*Zr�Ո��!��&pe-`/��;��%��d�A$I��f��he��������:�X��䁱���-Q0�7,�{�BFh0OL!�����}��4��˖ſ"�q�`̰ ��i��?�lɪC/u��y�< �%ߥ�a�9�Lt<���t����E��l(�����:��-��͹�45����d%�R�%�~t���m��
]Q�W��|`C���.VIzB�e{�����6
�ⱷ��\����&��W3�词 e(�`t�p��+�A���ym6�Z��	s�b!sgu�Tc$j0��V��h�h�Oֲ�R�R�����W0Y���֩�&�b��*p�U����~�l��0��^�R]5���6��J�JpXMm����ٙ�(�/�.lV\�p��[$�V6�^s `�$0\����rb��:Y$�V��D7π�Em�m?� ��� �mEd㩄��Vj�(V[bL��1�N�y1�-�-�"^"ک�����l�4��W+Y%��j��2�3��P�����BRNK�7Iǫ4�i���{�#,����`��n�Q�(s~;bی�����l<�$�F��YA��XQf�FIo����	�v��o����ҧ� ����lUK�iA�Y?N��;�J\	�Ć��tR�\��Z�����	�`0K����P$���d���g'?hSe?9��٭�hU�d�������mppwG�[��K��DR����K9!��}�����4��I���������=���Z��Za�n��")�E'�����vOA����fٿo:��)�����)�N!U;���$�].
G���s�<�:�V�]��9v�D_� ���\�j���U�#Iy�` �ܸ�l=��h�JVBR�\��@gGůͥ�ڈB�r5��t5edZ�w���v5�X��?�t���J�x��PМ䔠]����7�?"؅v<P\��N(5�|Q'|�V��N�DT?�ׄN®⊘��@�����c5�:�4*�����U%6:,i#�ճs�u��I=)���ɮ��+��!�E��ࡠ��>��x	�Z����6?�;��Q���d����9\wgBL�ո͐�d� ��7���d���=Ͼ;Z�ŏ�zF�8�z�s��~��p���V�Ľ��}���m{�I[�/@���������m�?���!u"���?����vfTWk��U^2=�
k56�*���9���.�<9�Y��kf<	�]d.88�Ʀ��B�jku#��9b�ݕ�r�s��P�����=��P�5��4C���A	~�ST�];�".��TˤlE� �%\9PG^�4Z��
�t�5���9�ԁ��Me=d�j	}���}�z�_[�z�(�XzS�P�8�\'i>#j}��+#��r}P�ה9N�J�B7&�u�����jr�({G�'{7)��T$��s��t�MG�w���&�l�靆�N�o���v�FR�A�J�6=����8�_X�p� ��mc/5�ڸ�����dy
?o��RusH3{3�ջ�Q�]��}xJ��r���"�H�B.ڦr�`C.n�{P��h+�֚mp�
��r[�T"�?��<{�D�#��ߜ�$+�f"�"�Ε�8h��i����QPkFG����1&��U԰����'˨���e<[w[�lq1B�r�>G��BA
d��'	M�m'�X�|�"ˠ����K[d+�}$�һd��2��tE��Z���o5�\RO3*�;���*uOx�-=l_`Z���n����->�d�M��W��h_OE�mu��>�9�����i�?���uX{�Ԯ��B.�ah���\���rW�:�?��m��#�7�Z�!��h	�;�BT�_��W1�U�״�q�H�����w2}	�L6�x��d�f��,� ױ�-��l��Ȩ�Z48�9ں���
�V�~+�k��#����L���=�I���hP� �*�f��ݑ.���kYڱt�p?TN�� �:��x �#w�7.����r����{�#�=�}s�z�Βf�ᢦy���ꅲG�zK%͚�a4(��gi)��v�M����!lr�&.��:Q'�7H�	ߥ�����
7���Z��� 9��.'�ʏ�o��=����J ��듾L�������Ȋ|9�t���E�F�A|5*9�	M`x��Ӄ�S�n���.o	圚lo`;��kެ�h���A�GB�T=FAH��d�zf3L�A��mk��m�!�SQP-JbP(m��\������R�)��8�����3!���WIsW�am�[��Qwm���竧��t@�C�,
k���y@�|�ӣ}�nkO�z�鶑Cs�nJ��eQB�2���F�!��Is���̡��$��dJAdK�����6��=��d9����#5"7�i��gwZ��,v(�G����O6X"��÷i�S��d�s��a�	��_����p2��=�ٵ:��q*a�^�Z�vmOy&�ƃ�$�#&C����[�00���	�&㱟��D���!�T7}�og�Mvg�.4B7���t7m	����&�+&���S�Èj�􂀕�Y�~�m Z,=�O�u�������@v4�F� ���3�QI��f���u,k�8��ċ� f�)=�9�V��dv{"�5�Af/	.�%�	,>Dד5.bf�[�̆�R�r�3�����p�&������vlw��J�%�Ԁ#Z��0c�#	ʩ4:L��F$�b����Y�e!�RmvZb�C�"<��P��N����t�4��>�Oe���å�kSGk������KV����HV�Bj=��� �*�����o��"�ӛKK,3g�܅��я�-	����� 4dh��(	�hm�\���ʰH��BY4Z�O�<z����T(X`M\r�Pc��V�"Κxy/�}6�?2�+��t@��20&�8V��@�4\���a,��X����c&�      �   1  x��ko�6��+��(Z`sX��I��y��m��m��8l����XI4D�{�b����$�)>l�bcѢ�%rf83�Gj�A�(�y�%( g�n	���&����+4�Y�R���eI��ܑ8��������$$��� ���'���IȮN;���4�i���a���Y�0 v��C���0�L�ӯ� �h��Q�5��QH(C�-��;C_��zZ�
�<O1��_���/�s���a9���?��a�F�dc&c��i�!v+�F9ڿg%1�U>�/��n���|�Ro��9�6Ջsn8�#S��T��P?JjK�����M9���H��[�0��A��[Pq����p煖)ŏ��>6�ʕ\����R�\�j #�u��K�F9��Z�qTY�c�O����4b�a�&f��13"�S��;MPB��b�b��Z\��<&p>�~5�m}��#���\9�_�'g��+�@�S�!��(�x�\�P/T���pa�r�ʻ����1|D�%k���\Ar��QUX���_�ݨ�wU�X��X[,���2T���X���ky�p�y�[?o��wy�*v�ݡ��0
��R5I9�Eϭ<S�.r��:�����LK�y��_���<�	�i���u8���2h1�A0�d��B�#*^��G�$�y��
&��Dk?�/�Gx��ڰ?�٤J������5S�ZRχ�p�s~unP�7�(��&�N�OsB¶�+E�oSUg��.wj$�VU&;d���ޥ�k���"6Fr5C>qgf�km&�٤�9F$c�B>�̩�"���!���K�]�����eU�
��	��6Q���ysP��@
>���FԱ~��Ɲ��9IR��vV�>}�Zc��o�o�b�Ʌ�D�J�6Ƣ����3~)-Wdn?͇�6��(u�H��n<�­���6*��0��w���dY�i5I9}w5ƎJ7[���-�@��4S�7�D@_��G�>ݎ'1XWZP��7(FS�B�������v�7$�)����
��s]�ѵ�C=36��r���o���TUO�(�5.��U��t1��������GI.l���-�^,�����_s�J�:�X��>3�\���m	5��9���t�R�?n]xB-��cΤ����E����P�w;,T�yaΧr��S�όS���P�5gS���E����R�e0YӉ��ު���u�G��]#$/4�=�Q�[��*J��g=�ٛ<U�W��C�"����Dg���R��z�ə�.p�H�8E|*?�k4�������P��c��XU6G90��95T(��1�f��nH����N�$\��Wd$0�3<��n�tG:�시c�����_�\0F���e~�8]z��%����Q��xd��qŶ_��xIS)�X��|>�v���V�C�N��dY5��E�������#[{>�:�����*]T��pdoN�nЎܘ���T�]ږ�4t�пmĜH�CvL�"�7gՆ{�1i��]�۪���8a�$������B:��6S����<	d��-������7.�bT��[0�-�����ϱ��X������u����(;E/�ɷ�7O.�M.��N������(-���3���IG�z�H��/Z��E�,Q�5�9��y�e��%�����c��♨��No=�NP����0^�{�`+	�d�ݎ�Ze��\��y۾ck�E0�&��wk�q��]ީ��ި���ڴo�ūQ���L���Ƹ��m
DOY
���������F�l{���i�	�NzGl�ֶ	,���r�}HH��)��a��?U�NH��L0o�FS�d�>��B�Ц��]��(bX�;'���]W��)��(!jr��Ȼ�W��b���?���즸�
����#k���iV^eYc,+�2�T����30���S�r�&PEj�q� �Q������\��V24'��@�v�]��o8�!���S�6tZ�Q����h����!�V�ͳi�Q��u�s�B1ٲ-���b���UN�an��|%���k�2��/5Õ��)����m2U|y�y�����U�yl���i����V��!Hp*������V�(�pԸiB"�rԔ�ՒI��׫�([!N��#I%��f�W �t.%NļC��QR��T�+�8�,r���J��;�ߑ��+Y�ۉl�˕���0���l�Cp�X����j3N}&ɧǄdsWF����{	�P�iz�k�Tp_�4]NF�<���,��=i���ս����u��#�;��e��U�j��l���xf�7�0G[�Ch�d������J�(I�G[��m���F��Xi��Zc��5J����,�`0����)Ka��*!*�*���ZW^ǏE�?�)��&B�_xЭOZ�P�T�d��+��/�*gO��8n#n1Z4B�����1:F��,���}h�/è�^2�)s��������f�f`)Pad��@��U���%+��Y�ĝ��5)���a�I��9�9T��ݡI��d�s������3JK갸��K��x�a�r%}��-�o�&)d���;%!&@��c�k��B 1��Z�y,�L�&��[�3���rv�YW)�k���������!����oB&&��깜$�s�ߞ�E������tt�����Q�C�o�C3�ϴ��2%|�f�ϵ�a�2��Ҟ��u��T��تy2wp��<�M˵�]�Z�����X�m�go��Rȕ��%������K��J:��0������x������!��!��t�1��gC�G�ů���Y�8��?c�+�<ֱ��n�?�vrr�?��	      �      x������ � �      �      x������ � �      �   k  x��T�R�0=g�b��Aǀ�+����Ca�xY B��0I�L���
8�����v�}����W�F;��8á��.(ujT*��YV@��GI�p�H)lh�<i���������99�b�B{l��n�be��W<���~�`,�ca��c�c�lHn�1i��e��<�a�b�R��HR��ʜt'c�`����^��(y�G��U��	�#{�f��x�u>�-v��t�|��7�x�G&$���T��fS���r�\�s6r�b4�2�>ÁX����m?�h{��^u�t�8 ���cJVV�<V<d{���h?WY���ǆ��]� oT�����ws�Y�Bj�Nŀ�X���v"qw �7ȮU      �   �  x�]V9�%7�[�1DR�С���L0�D��o.���/��"Yj���G�?��뿟���� �o���o@���Y����2�C��g�@�i�@�K�od�I����8�ف@���,m�@0N���.��Y� �Y=����GG t��W.z����f���B;�G�$	�g�hF�c�˝)f�55Z��u��φ�q�/�Zl��rzX��l����4�tk�p���yo�i+b��n>y�]P�QKi�F@o2��vO��HN��u,h�7�g����6 'h���㖰 ���#%H@MG0�X��:��T� NM�A�F�5�p��j�����#0ڭasw*fr *fv *ְؗ\�<��=�I��Ԡ��@�<�zy: S�� �Ձ�ya��g⫫��T'�6��bB�Ȧ��	ȓ�Ȃq�%�\���z�@�t�٨kb�oQ@z�'J��ŉ�'5z	4�O���9�V�V��ⷃ[�J.e�ȥܠ��Z.��֨�%��m��k"x�&8�U�Fc٫P
'��Ҹ�tQ4��ejĒ~@Śnoʦp�����ȶ
2P�Ob�m���
��y��.�I�$Ǐ�\�;ӓ�f�tLO��|��v�輱�Yy�B�B���Z�
��&`����uuf@�:�����'ݱ�:���7��pa�!_b�|e�qR�p�9%j �+4	:�ňǳ4�ҏ�4��ϣ�)���S�N�Bm�q��P:P~N��	M�a���%}�)or̦��fĲ�����[�H3�K�m��>�}I@@�r ���a'މ���e�ad��=|e������P�wᖊ`�C,?�d�}�����,Jo��T%��ǝ@V|���e��#N@�O"��D˨������)T濰��35�K�J�0��Ux�} ����%���o�`�����O�b�N��"��Pbhi���h������      �   �   x�M�9n1��c��+�?�-8_��M%CAKգ���y�_�ϯ9�R1�<�mY)�u������'Ns���e4��m�T�f�N{	$8�]�@߇@}���ze��o���6�s5-�-B @?R A?J�@?�@��c
LЏ%�@?���l�b�{Uַ-ö��D�)B�-���EXz�kO�q�S��$���iH���S�ȶ�S�ȴ�ӚȲ������$~� ��ɕ�      �      x������ � �      �      x������ � �      �      x������ � �      �      x��}is�F��gϯ�8&�䬤�s��HJ�G<�U�ױ�@�U 	�
�)�Ȧw��o��� �"�옑Y@��2ߝ����?���.��t�%eZ� ���_��hoZ��$�[t\T��EZݦi-��^�e�L�*�.�$���hX%ղ`{�l��w?���7<�|�7:�ϫ1�+�����1F%%�o=��^�%������R�1�<ΓY��-˪����<�wP�?�"����u���2�Nb�<W��y��o.It���,��M�(:�Ϋ���g�i��b�iR��e6N�t4��a�ˋ�n������w�^!vy��EV,��N������&U��!�-"�\B[�����Ҳ�.��tP�V���[�po� ��$��48[�wjW�,}�n0:x����������m��� �#���������wá���%�H�i��isk��8Rֆ��sN@�}�S�8�>���u�ga�a.�kb�f�#��T�2]y��پO�NcƔQ%F�z
 ��"ͫ�tQL��*�T,�T�����5|m�7B�^C�`�%1���󟣵9��	����p#�$�8�O��4� � R�&�\�i���0��<� �N��(�]���:�G�K���a�Z�9j��s0K2e `Ƴ8�o�0{E^%��i:F���"f��a-�E:�+�F���S0�͔����ԯ��`�Uf%x�"`T�Xh��/�}�������HƊ�� ڦ���H$�XsN��o@afz���c�7.�y����娨���|��p9;�/�L�����?��Ғ��D?��D�����}G� ��0�)Q��?Ek�I���`�W�b9�%�e�Zܓ%�����q�,������z�?>��ߒ������|���|s����,�ɸ�`; �~���&��^f)s?����+x
૛d�.p�"TI&�4�k��5���7�
���B�kzuS.g*T�Wo���������y��'�4���h@y  �)��*�+�|��@.�'�A"-=�ms���X�rPHV���5���a#hA�F�0��4���a��=-C��˰9��f�D��"j~��=h[otn����Q1I�8Q+�~�> ��r������ k<A�zF�3���g=#��Z���2��0�D���%�1�e����bpQ�PÇlZ�Q��r@7����Q:ɮ��ܹ�M��?���F�|��wW`�l �p{��y����B)���������5ngd���e��zT`=�79	sn����:V���?�RT]��(8T�����E'(:A�	�ΣTt��&~lڎޫ¨R�<U�8�����$>NG����sx�hc�����a�f��p��
&W�\l��4���Q��<���RT�U��Ѿ<��=���v}#������`���e�p�k����A�v��G��P�N��	M hA�@��&4����у��QDT9�?�'��W�`Вȃ-b�va�|7M��u1���2��GG���[d�l�iV^�i��U�Ϫg��Y�0:d��ɇ�hT��eo�E���*�C�YPQ�o���.e[�ֵ�@b�,�¾��9���DM�'�_6�ܥ�Q�WA�
�UP��r���\�*(W���G�f�u�4�Z6��[�k[@��n��+
���J�PN�|8wdJ(һ�]%����h­�_�X2x��B���{���`�v�V�{6�Ja�^:˖�����Oi2�����*�ݞ������6�c�(��J���Д�Xu�:��]#8��u��X�с̋i6��'i9^ds$���i�^fQ%uW��*�'���#�FT٣d�
J����#��~DPD�<;�r��>��㺶�EQ�1Y��w��=��!��� j�5�֣4��7"�G��T��d�UiF�Y�7Л��ɺ=�?|E���`�(Ű��_q2F�KDz��'7�O�*AR�X�(YW����G�ʧ$6����e���J�玿��xA]����a�Cj4{AE�I@��6L}�6p+L�TU���W9�E�g/.�t�ҫ$[��_	D)��m�2n� UΫ��]�!�ï��y�a�K l4��{Rh��L�)�HW��J�#�*�����?j���	�@^?����x��ݷo�F��4g���;����ȇZ��h�Y������-�c���h��3�w���*��|M�{q��`+��ŕ�⼢w���y���QR~��IV��h:k{'�{�Q��p}-��^\f��!�U�iv�%��qL5��D�v8T�S�UL@�Ϊ)j�+�1�?Gs�e|�����!�=��y�etp��g�TqZ���'��E2��t���V'.��Nʌ��I�\69�o��EJ��$t>_N��y�O�&ˣu@&�q����>$�p��Y�>\�d�TzJ~f��P,�6�0�jP��jǇ9{��e�R@�`�v-j��o�ͩ��������h=Ang�v�EZت���hw���&g�;�ݎ/�ÛX{z���+L!Iup�W\p�W\p�W\p�=W�#��Y��:�q��'-/�H�zy��		V���P���>!���� 0n��3��d̸�T�!v���Y�(���MCjƬ���+U\���Z ��Σ�_��	��u� kj�a,.�-��L�@8oy��~ri�4�d�@ʴظ4K*Jp�sd�!]��ႁ�2>b�!���� ��)���a�L=�:PuS��	oRi����m���ب���c���|��]Gפ�)M�����?(�A�
~P�B6�{Q���^ҽ;���g2yIS��'��{Y=Ô1�)Pw.�iV�6�x���ius�>O3��E�+l"�y��yM�3]j��G�{���r[���cP���.Ɠ���԰WZ�l'��{T����,�dA%*YPɂJT���s�ܭ����
�B�U;盹o�lP)��Gu{����w(��&0�~o������F@-��������t4�Gi�{��:/�)Qw�S(G�E�H%�/��&��4��o�HeW������V��rۮ�hj�(��mW�C�ܢ�FmQ=�w�d� �>��-exf���YZ��*(��Ѯ	�
��ԋO従RB>u�:�h�p��Y���F�.�j9K�ŋY��*��ש������A��&y�I�
|��N)W�m/e����'f�0��P����'�,|���q_N:Q� "����c�+�z����`�c6؛5�=	Ob_�?]#X����,����� �!=�ߣE�Y8��8߇@�$�j�>J�����|�Lɐ���Z%\��M����o��D�ܺ)�KӒeC��j�f�+J;:�����6F�wum/��3m������d,�z�!~A�'5�nց�
./V{�b�|U5p.��uQ�Z��ν׋�����G�}(�3a#�w�����-\�۫q-���K��#�� ���˾�αo��`{V<�p���f�z�m��.��|��	�^Vx[�s�+ל8�>o�m�rKNaq�B�{ B�҉S��@���P^��[c �-4,X8�Ngi�_� ���ɗ�Xq>��I�?g���1�7�LÞ��4�!�xR����X�ɹa���t�W����Iv�M�ɴt�o��jq�jG�����x�\�:�xMwW��8�=Kqs���[��H�$"�l��fN�=J:���������}�L�ŝ9���V�˷oA�� Wj��r[�#��%��)�]@�X4wp����� ݡ[������]�*��N����{X`d�M}��'���S��V����Z����c/�`��0��y�ةR"�a�4�7���>�1Ҋz\H|�;����;;�"���!�<Q�k�NS��Pa���R�9�J�E�爧���f����:�5B�p�h�T�DmC?EV&q��@^��3�q^��%�ƏnD��]N��b�r-d8z�	����q[�a�pX�L>6@���f��c�%���?�ټ!T��ۼ�bUvJ    ,�M����|0y���ye�,�f_���po�*k�k�2��5���_CX(Xc�-waS�O����y�j����uy4t��&�
�&�$��ލ���!�FQ�gz����G_��ͨ�N��{�����t�	u��f:�����0�.�O�6��^��D�����hH/=������A+�ܲ�G餼�C�)��H1�`>�?	D��\���X���w�ʬ��I���Gc����u߽ا���Й=4���Q����,���,)o�i��-�m�Og��"�_gc�;B�-<�a����-L!��戁HWiSu��WmSh11�}��73�1�Qe�o2YN+��PK�[���4�?�Z��3��.�\��:�i69 ��aP�3��d��c�/���*)���@F�#9����9iK���Z�Nyw���Z��Hq�U�>q�-�/@�^R�7�	�����5��mY���g�+�jׯ�Yv���z�Խ3�q���s��k'��W]/�F�x�8b0=8��X:�6z*4��k6�։}�Xg�&Z�q�:�錴� 3�x���kQ��^��,뀖n��\lZ%�s�Ԟ}��}�p��C�8Y����-n��B�N�?��4�ǩ�{��s9�UJ�x���;�!���x���7~��>]�l�7jp��_���<]�� E���/9]�D�6x��'���wT'?�@:�"��3t�;c'9F'�3�e} ��|�����)\�D��i:�H�_k�
I
�,��p�x՘6�.��6M����ۯ����jrƟ�aJ�ؾ�-����5~PF����K��[k����"��Z���Zt8��OF��ϟ�E�dm@���
3h��m��3�֯z�0��x��K��+���X��{�{F4��ƽ�B=װ�`o�KϵeW�n�C�1�5O�i�K{o^
�I�ܕl5I����&|��A�UӔ�A��f��s�z���4�ކ���E��!t�.����5mi��DHD���AX�4��t��2�3��>�LU�"�<���5g|���2>�Ѐ�1{%�2���a�uS����T"2����+C�	�e��/ȯ�$�(-װi�H#��(W�OI�c�t� H.5�R�k���P�҈���g=.=���	�o����D<��B�0ȫZ�����IəO 2��d"��a �u�,�t�ڼ��x�+x���z��z��c�4@]_��
o|	6���E��b��rZ���ܼ����3�/ј���e�x8��K(��[��Dv�d�V`L6�ү��^`n��6����wQ�i�:X�P��=���<?l-}�/O-Q{u%
�~wѵ���/o *���DDx�UǼ�N���{��x�!	���ί?�����dI��_��d�)tr�Z+'��'��-�J�-�P�h���
Ij�� L�mhے�����Eu:*��m^ɽ���(�}��2�*���٢�a����D�I 1Su�G��?�u���6T�JԮ����	�f��+c��wR{�p�D?�2:8�����q[�=֜p����ػ���
��3Mfet4��<�'M���L%���Y&IѺ,|8L�P.n�q*=%���*8��t�"2��I�1ְ�d�5g��pд�'cW��Yl���Bf-�OvoG'طh��l�6/^�4)_~#�%��H����f;M���<��d>�?E� p��������4Y�D��D�� l�;ىg��4�L�Qs�}��5�#��k{J�z�e�/�/g�)�+�258s�-��$����`X�����)k6<���Kv��N�g(��"�7Ǫ!]Y/x C\�S��I�v���uB�Ҝncc���-�T �0Q��=#G	W���vC�HMiH�,�_:kcB�(�|�[Bq�P2�ugBݙPw�	՝y��!WTQ�{�(���'��*��D=%������q���$S𩋼6�B�h2��"�|��дKT��/�D���PFg�G��OF�`:����V�p��]-���R�㤎K���ux�h���]�㨼��X@��ŝu�6���V�����%�r�j1�3i�W�{�7R�L�e�6!h�5���P�-����� X�0[�ݷM�>���4�ͼ�u �9���x䕱璂9;j�9,�A[�eu��W�סƾ�<b_��@��'�*�`�x�؛w���o�iv��|��+���&_F�^{�b��`#��0�����p������$$�'�ު�[��7A���棸��V;R0[w��0j�����g)�7Љ�[���n���|8��
��4��8�8Ю���Ie|�|��������p���
n��A]�H��,-Y�i�5>K�)�'��ج�ͬVQ�#�kh�b���.��N��my�nP�]��ʴ[fb��l%��8�X��Jc.��ჺ�"o�0��˺�0Zh�Y4�jE+)][s�H~��Ά�i�:���XӪ�}�Ϗ����0��>��l�i�G��]hgT m��p��][�gC�O����\�]d�K0{�L��J2E�{�-��L�]�K��ng>$���g�n�D�4��F�~maf��#�xr~-���w�5"��bB����1�#��h����acN8���)^JIu5E��
��\�:�OV��״�����~��y�Y5�j ��b�� �W�S���gͪu���P�����'�m]��,�)��륧��O���$	��b?�#WQY`��?{�i�H�C.�����q��c���֓�ϭ���Ij�+��B,�S䆫�+���{��/7-&NseG�����������������%[��[�c��}���/�-td��u���!؏~�ęv��V�!�u�?��;z60���<V��`��`���o�I��:�T�O� ĩ�O��xq�N��n�oA1i	���0��z8<���tJ4�z�2h$$�yN[��4��A�$d��Fɟcz>i"��Oh,��,�,4��I�g�erل\6!�M�erل\6!�M�\6�r=�Ԋ4�eUZ]=�U������j�P�NV�1�gQ2t;�O�ZiNriWU"��?Prf�>eՐT��h�M����X���X���1�]F�K�/2��s�3O���О,+d)�<촇9{Do8M����$($A!	
IPH�B��@!ѩ$z]�;�D���?�)���,+�������X�i�Q򭽲Ѭe�V������V{�G�$���T�~�9�����jAP�ZԂ�� �A-x<�����aQ>���*O�����=��������5k�o��/�{~��R�L�.�>|���w���`�,�D�{��S�K<�K;!��iE��}�-���]�i��ڦ�ú�C�w�(�l,8v�ۙ	 �)��̌sƳ�"����T��3�1>�舘�ׁB=J"I��BIT��	�x�3Sz��9֤Ӌ_��'g�g�C����n,�ܹu�H�T������ h�^T��Z�rWSd�d3GF��������أi�������!�,�.�y�r�;�qX7���XV^]�p�5}Y����)�\@��1�{��,/_ڮ.���ַ�	��(�;�`^L��]��WI�����l�7Z��`p�릁=��v
��>�E�����d����W�Udݕ��w�QB�Q��ۍtY�a��/`?�d�����W"k9]��l9�R���$���o\u(����G��/��^"e�~W�|�(ʲ�G��9ίS�]���'��oG`�M��j�c��E�eе�cжe7�������H��+#���X;O�:�U��u¤!]���|tB�R���>�jT��HR�������,*�$"H "1� "�N�L�ŝ���{g6Fr��R�Y4V�U�!�a�(sy�ʒZ��׵�]Q��\�����Q��dŲ���da[:����R�? �w�I/�9��h�rP�g�1 t_@�qN~qs��,'�A�<>�T�ܱ�b�r �H�Ad�Z@;�-L��B�=��<�&v�t��e�.� X�~X0��Y�'��<��A�d�f�M��{'DVb�f    �Rw�rM��D���W������Ĵ�e���d�|4"��.S�)L�-dG�"�-T��֢/�x�a
\Me��lId�`P#1�>��BŌ�2J����R��@@Ң�@DhJh� �Sx�N�\��`r�O��l�L�e�Pq�jP�ĢV�YA<��&M��!��e�����^��%��onf������㽑.�!B㴧J��p{���-����������S��|�ѧI���g�@�V�.�r��f�i��f�y�$��y�%�=��m�h@�!n�>|�v�Q/1��������8K�c`_��]Q1�=ɾ��N	OGaY�$��}+ι�`�{.����L|��ݺ��Q�Yu'�$��ލ���1�FQ�gz��;��*n�N��������e`�O�����G�=���y�5���h$�WR�(�`>w)$ (�KA,��$ϗ6� �G_����C�,��w-�rx�����'6p;nG�����%�mD����|Q<_�]:�ю�tQ�g��ט�ٞf��s�X��ӗ���.R����� �ى�G�3�>\]�Tw�Nq�NqgL�������h��ȝ1u�
Cv~"!��!�ʭ���Ϣ�O��"�%�X7R�v��$-�c�?��XX��N�(�F���v좎��7���S��}&3� +XΖS
��ebp0� �gI]�����J��+s�������s'�u�@���<��6�v���ps�,�A�x�҅H���1P���M�M��1��Q�^*Љn�?�=�C2x4���7�r�X��f.����y.�)�trÄb%��OZ��	��a�N
��dQV���e�m�j�	,�bk����O�����Dy�py�:����"iBRC��9Y~e�D���q�iC�J��<�+�߫=D����d���d�q��	~�a��:���2
خ\^����jǚn�*���|�{T��Hρt�����o���
R/0ܫI� ��3�����^�t�c�[:��!z�{H�pQ�ً�"]�I�j!Im7JP�ئ���p'�{�Q��p}-Z{���٢��PuoQ`��pz�0���c}b�i�؋?���ʪ)�G���q�����V��cD�V�#�� @�V�!�s�e��\��A*#���/M<�}K�f	�vRf��O�Rd& ��ٹ# /�`2I>iZ�,������4�w]>�yV�7�8���_@Њ Npjkl�7R
5�j5k8���ͭ5w����kbrfes�}W�
��έ����Q@��:SZ�]����n_A��+��׎��`9�*�s���% ��	|	��#&����2���I���4Ӊ�B�<��Z!�y���1�JHE�����0F�]K�ʹ�h�y8C��" �(�mS����{����c7١0�ܡ����V����=- mqn�w/�C�b��PB�{�T?��xl_Rh袭��i\��t�]�ӹ{C�Ś0i� ���Q��*E@�=T���ڰ���&�g��5����{�0���M�'�zuW�^���{��n�mm=��γD0�6�|FuU�1j�:��u���ptvx���lB+ܼ~�������P�ݷo�F��4g���`Z���y�pIg�8AӷyE@��m#�
YE���I��T�g[����7I�W^,W/� ;\^0�5���e2�8��,�qZn@�F�r���M���ݵyZ����b�i�V���T�"e:MǕ䖽�/�bU�[�+��Z��?�X�4 �ƉY����X@����m��W�U)����k*h`-|���c���l�R
0�Jhco�����f�u���}�"���k5���R���	��c�z�w5n��b:��Y�7��Q���N��=
�P��?}��O�as2l8BԎdL� ��2�CyWB OTZ�V\�/�?�[i���*>�cX;�P,+��f R�L��ch��_$�j=?���,�7 yn�Ll����g�Ʌ�h���rvvp<�aA��hptꏞ0��,_V0-Jqu�N����O��ea7IpF���x�|K�J�P�?P?<��<[�:�l*�+i��H�혯l	�7���Ϛ���v�@����h���8�����ȼ�P��V_�^��ʰ0����_�L_�=�r�O�opS�g֖� -����P��,g��55�?� ���sD��~A?pAZ5�������������v�o��e7c���	�� ��`���&HJ8<Ag�<O�y�4�l�]S��D�ϑ��MJ�h;oE���Hr�c��YuW+�Y>��BD�]D�>m���Ύ�C.G\��`�g88�r&)vYec�5(�eಁ�.K(?����Wz��Y��5k�u	-_)�n�8�6<F����oV�S᪩@�iFl���]�9��c�ohԚ>����ʉ]�W��c6�:(�5�pMn�#���g����^i���(�4�Z?ܘ���0g?��(Z��2 �Q ���Z��T$׏������[%N'���q�etp�qe����֩�����þ1]od�TM�M��mC��H0x�[Y�C�����)��BN�'U0jh���#�@v��D�TW�Jtׄ���$��/>b&�-�f�H�����&���i�k^T�n�P��w��ss��i�psj��66u�`o�h�����6�D����qJ$�+����U�Y���$FG)����A�]T��'떓�%ˣ�<����4�D	Oj<�R>��Ô锱x�J�,Q���~>�z�#*���$���)�,U��qr����t����I3��D�5Hy_�e:�6]
�[��낅,q'�4����%	��6݅��Ӣ)���g ���A��$N��Ƽo��<���ڬ'�Ӗ���)%Ip>@�S
jQ�oAw�{Bս9t��i	zB�(�[ӝ!�/��؍��Tj]p��g	*^�2��n����D]咃���wF��|���]�}�3<���r�)��t�����>�_ñ����༴��+Z�x�fM�
H7��2�G~�&חf�Mwwek[s;O+��X�d�dV��}�ת����f{���c�+�P�ä�
M��䈼Ŵ��Dz�b�1�0�F����=x,%K����H��r/"��Y����60���E��ڿg��?�&��*��)�� ]��2�Av�ܞ�@i�.��AhR��CēI#6�m�xJ�D�h�.-}��^l�+x�r�����p����������kDVY��*�2���"b<0��8c�٩U���6�.�t�F�2X܀
n	��́���l�{��%�4�6��)������T������V�9X[9L�bF7m���ȏ�jʉ7�TR�|�z�ۦ�6���4�[��2���*d��:[�v˶��74��������u����)-b��J�E��,�^���=Eշ���{5�wx��וx]g��u]����у_^f�z���|�M�{�jl~N>�~}|_4��,�3���r��'L-����F��iJ�HyU�CEi�����kLغ�{m��>����4+�ҞfE�&��<*L O����yV|dt�Z	��݋d_��v6mm���,�v�}���G�ٻ�X ��,L�*���"��m�����A��?>ko��K�ln�x}�&��M�iKi�X�O=e.���Cm�&�F#��Y��$�,1���h
Uo�+y�M��F��ϥ[T���g����~ﴐ�_��*l�m$����T8q��� �R���t�]t���,Qm!��z^���g��+$H[���;�N���_�����3_%��2hZ½6[~��)Lo�a�
�X����eq�'��K�5�j�2 ��r	>>�{�z�SHH�,;8)Ϥb�$��(���H�6�^tݛ�\y�k��"��<6$~׭��&V�r29;a�57L�����fa$�����>�q��LQ��yP>���Ho����/�m���
�O���IC�3w<�M�X�g�HU1�oaSk    ��i��_�w��Dl����a�T%E��|���@����QP����S;��@��'�^�V������������C>��Φ7R񫘗�L���Z��[���v�PZO����꒰Yp�;�?l�Ղ�M��%MK�*����!��d���*�k�5qe����G}/nߍ�T����[�U��k�%w����q��<��K��:�q��g]"E�b(']6�f@Q��(	_,�G2���m�r����t8��L�"�7 �)��ed�M�XI֔�1���[I�+��`��皸�Ր\�$(n�ۧ�L�Z�>=��]�H��'N��b��H);bR��R�lPM�jҬ��e]9FP�zS���~�0��V������X����k�����Z[�ѵZ mҵ�{'{��U-f��֊�-�2��xQ12�G�I�ر��rU�`"�j ��r ^y#\c�P=]���E�^�����5j���=Ͽ{eu{E
d�� G�2�!n ����2tt*L`�ۡ2�g�OeLgg�����(�N��)��U3��&ڂ?�#r���7b~vֆjƧ@þ,����{�z�u�������\@i�Sỷ;>u���~��%�-fIy�M3��}���cB���a~	�nt��Mh<�E
(WZ�	���gL��(������"�����|������]���õ��6_�y�f{��6E����P%�@f�����0i�H;H"�X��5�2'%�H�^����Nd��Z�|��Y���d4��I`	�ѽ	F���y$jLq���b��E�rɚo��L�c<'�N`�Ԅ����L�^�]����% j��]�����H�mw��a�7͠Q�>̳*K�b��޶~cXuOH&D�� �J�?�"�����#�E�I�ԍ���R�ڞ��v$���Rw�~!�:���Rlg���^(t�\�,�E��l���x��\�I�5�UϠ<����JZYq��_�x���oy�J7���{�2�l��1D��P��/�PVK�*m�]x�[#�ގ#YQ�����9?��w,4��-�A�SuEħ�l�l��I��U�w��>�H�����>�	<�T��6襲B�&����/,�M�	���9#5_�i�"	�Y/M}#K+m�&e�'�qZ�Q72�X�va>\n��y����F��F��ʭ���#*�z8�7=�M�T�'�,¹�|.��ԝJc�~$��;I��?���Y;b�d�6$5�:J� ���'q~�h�O���	�B&dQ��9C.(ݗ1	ۏqؾk;o݌ו����#���|"���!H�7�0��@�:��1���,�7@E��gp@���X	�z;�c�ؓ��i�a�
o/Ϫ�k�H 	Js�����!;i��O���ٿ
X̱���EҰ@��7��x���hjd������J8���pC�����E1Mٕ{�����������x�@�Ր�����~��!��T,�g��ڛ�eSLC;}rB��s�~��S�vx���㢊7I6���|����	��޸��~�8�q`"N���R�[��qX,�����ޝ��)������'���6�a8onB^������jJ�Ѡ.:��?�z
��f1tmf>�0`���3��~T�����0���1�g=��ԙ���T}�=�4񒝆s"a�k�� ��[6��")d��P:����aSd�]���3��r�|3���7��A-���#t��jT�.�EbS�L�]���c��#�;Y�������a�Mӯ�4�U5�1[�~Ϫ�,��0m�}�^��V�p��s	���.N���
�'O�v��;@��^���Nb��[G̦�&��e\��r#���7Z���E>Y�x�������k���>}��}wt�n8\C���f�o�B��Z
+FQͲ�~+�ʣK7����\Z�(X���|�}����� �VH�4����ҍ	�]��K'Kcmkn�f�����L��B�֚����Um r�W)�v��ڪ�Hw����H��ސ�B�Ϸެ�A�3��Y�nw�[�zN}�~�~w_�~w6��l�/@���+�������ː�z�?x��U ���Q㽥�8�/�6�N~���D_ ��V�%v�2'��t�;�Α;�reCu�'qP�+�O������n�WYA �Fֽ켕�/v4��I�i�O`WӮVrA���,L�����&W��
_/&�y?b�	'a�������eǼO���R��5u��f��_ͽ����;�������@�6�{�/�`�
�~l+=C���-��{׈�]*��P���c�7�6H��c�������.�z�L*��ڗ��V�3rC�8-@(YW8M-V5�bF�\���l��4��x�?�u�[�%���{ M�w`�˶D�m�{ [���]2�k�BF���:�HA���Z���Tk��H�;�2ÒH�8��[��`� �B�eD"��fl�q�|���q���h�J�?�����#ud��`*��oI�l�"���׭���)mv�����GJ�|�ҫf�};�Jt:e�q�μ2z���`N�$~�5��~�˿��.�@F�����F���s@��1@�p�*8�=�n�,�2��pd}����š�>��1h1b\U��)�h'Y��<��o����5q�1�3l��ۅn��+�>BZ�߷w_lrz��܅��G5E���=6���9<�?V�C^No;���.(���C�H���x3|S����C�_��9�u�ʐ�
v����D�mĿ�.�
L8����ފ��j� �@���崂)E��2g��XX��0�>�p�0g���>.��j�e
���H�"��u#����P-���,��t���IJ����m��A$ax�В&��J^��HiK����KX��r���u�8��������3n��_��Toe���R^�)r�����<��w�^!vy��EV��,@��C5�BC�c��h��Gh��O|�3��uP�6WAQW{��� p�T(�> �P�|H���������k&�# ��utxt@d*>�Ӥ��8R�����j�k�X���oc��"5�]׋q�^悿&.5i�#RmA�}�1�����i��*�J����=
@
g�g���*�`���!�[��W��0�+�fE刄\8f��/'��X�#(
�>�J���>�ՠ�ep ��I����t@��<:^�?3�"�Q-��Y�) 3��)|����SX�@�1��_�0c<Xk���8f	2�g�=��	�o�,0�N�s�R���aV��ॊ�Qq ������Q�OF*2�C�R,�l�����rb��)��+�l�/�z��6�R�t�8S�g�G@�r��zMJ>
���g��+���pJEON�| �\;�P���,قy�nm�L�`�9`�r��y���^y��T�G�{���Sϰ�y�_5f��J�&6ՓU�{��[��� �Y{�����HMbJ�"���.E��z]��G�t�����Һq5tu�sq3��ו��/M_���MX���}])q�AM��r*j޲�y���3���=�<�T�Iv�h�X�_苽r�"��F�);L�H�o���_�\^��k�֏?���i���$�f\fT\1wY��t�4eE b+Dd&�Z���"��Դ\1@eH� 5*�H. �4�_C˽Chַ���|-�%�@N]j^ω(��G�CEHT�&l�6��6��=�M�/�@��c4͡�w��v3Т֍_؃p���΀�K����#5=�X&jz4W�G�f�W�I"��ŉZѲ��ZS˛��-Tq��
��^� ��V��5�V��阤�%�9���[h��k�E��F����n��?Z"J�W9\*8z��F��O-�|�t�^!�_�
��p��^���: ���Sy��������E�]����MkJhWRj����Yh�cD�w���`N���N������:��gI>��zw������Kl{�u�yv��T�ҳ�=�[V��%ч��Ӌ���oa�Ǜ2`K͘-��ő�"ok�?$�$�    V�+���8�pk��Z����7TY5M���/�̀��(�@4$zb@�Ġ��K{v���vTm�v��@�P�	o�eiԎ��m�������ĺ/���l|;i�_�l��WX�p����K�7��0�����������|����<�6N�o���N3��PN.Q���oU���I����I����y��ƅ��=2=n=�&|�}�1�%۠��w�S�Bi��	H�|�@%P@��#hX; �`hK��B8@J��Ei��vuq�+�����{h#
4��&T:�z�o���xHӺ^����yfL��$������5���xFLPھ����6�g���f/o ��+@-=�6�ce�c��Z�3;�Y���F0���	<61S���[d�ko`ޢ\k�d�"َ���v8v(���q�R[�푼\c��x$d��iҍl|��j���y$�������y��.���{�u���tt]��&kI���d��� #��[�Bva������M�?�/�n�sYV�����z��?�Ϳ�¡��mtV z��38䮓f;��4�����=�@���b"�l�H���r��Kѐ�jNy ^�nW��ϗ�������!��;�UУ���(�z"���[xC��VG��˧�R<�m���3Y��a��l|k��'oL��:#Z�Zk*k�O����E�`��SX�~�����Y�� �i���(F.� ŲՒP�V{hf��4ό@-��u)�H|)3S���u@�jL���#�./�ָ��': �*OS������:!���k��[�o�϶��rl�Q9x��]�"?�����a[y�E}��5m5~�zs���2OysG=��Ŏ��w��q�Nt�fY�7ݩ��nu����kptu��Qzy�5h�w�;w�냗�:�s��+����W���W���a�����lo�<�>|�f���Ύ�}=�������-km�����E���h�<�V�B���|�q�ab��p:���N��85c���Լ#
Y�P6��2���Q
l��+�7^���a��}�nK�H�OK�o7-� �ܣ���&��y��l�W!�����U�H���٢���Z�в�گ�ʠ�+-]%0��mӻ��h[cL-�M;�65��0:Ft�]6߰�~Q;�Y�Z�N�,�W�0둶ŗ�G�b���z�Xϰ�^	H������>1U����,=�{����A��8T��6�<⿨G�Ed׫��/����~�S^w9Z�W���&�t�B�B�ZQ!j!D-�����B��QS+����~k`�?x}s���=|�� L�ՖK9i�����
����{k�K�*�n	�vhF�E6��L�!Ƨ`u2c�fށ�$���	2�%j҉�@�NP�"wt�pE4���flB%� ���v*n��v��#mY;R�� �NĦ[k}Ku(�\*��Z���y��j�~�zv��鞦w��3S&�rf����vw����2������>�Yy��V��9͗Ţ1,j�1_Z�%�ԗ1�E�-��d�-��� �UJ�ϚJ1��W��:9}Z18�WŗK�9S��ĪI.�+�$�bI1}�!vO^��~��M��^��u���U����n���R�>7W��zW�6yX�)�>��>g�A2�rG�.��e\K�N�9�E�a�<�5f�1}��|����ݶ�|X�N�����P/
�'Ӏ�S�M*�QyV3:*�i���M�6��Wmn/_mӴ}��T�Ά��+�P�?:-��t1�s��:n������-\N��U�R*,�,���w.R�d��*pMP��}���ݲ�Ȇթ�SMSi��F������GH��N� �CHHӼ�e��45�F:|���%6>^�Q����*R>�9ˇ�6c�S�1Y�fw����� QM�$u��� ,˒9><9��?��X�'��t=ŜE�lmi�kBk����K��s:�ea}�T\��b\2 �׈Fws��� @m� �����\Ԙ�H�&�n��-� ��`��S<�&mFF�K�畴�\���Ĳ��D�g�*���CNny1�ǿٰ75��B�c���cAr��I�j�ᕹ�yd����:�Ҽhy$0�LܖgL$�2�R��|�M'z�D��鐧x+4)�N�E�,�	ԟ�)%��-*���<��ۄ��,�E��,�\��$�>"�QG�M@~�K�M�zBK�����,*��wZ��qZÇ��	Қ"�����ț�q������?����D�elo��G� �0�g��/j�M�ٸ��q�[ި�Yjb���&����7�Y�8!��O��:���l��D�|�w��.1��#����#Z*�9��rvvp<�a��p48:50�gli��K��p����vb�^�|Iz[9C� 54�r�+����J������VG��-���no;�*���*�ͪ�x�ݔ���yi�R� �W�cD�-9��X�t�b��&V���W��I]'�G��j����ks+�- [��z�e�o�5!r�������b�P�
��p[�ט�y���=���>e��1O�;�>9�;<��JNf�4��2~��Y��pΩ�ΫUֹj��=�W3�.���awM�Ռ��]]z�O���ջd�j݅{
��hλ� �l��>�Vl��Z�0siY�h�aܲfY�c�TYv�����`N�� fʄ����l�y�rC��ʂ�5�U3
��V@dE9M`{S���Իլ��}���J����f�%�Z錅~�)��H�[�)��Q׵�2	�p�-�t��^�1�a���;n��P~�|P~�j
(?xM�'?�DOl�q��V��գ��q�X��k̫�C�e8���r�%D94ٖ܉ܷ�<U�>]F%n~\�)#O�L���}�sm�n4j�����Rh�I7e�jka��rx�!�G��rx�!�G��a�E.bS��f�0jT��Eu�]�#�x����ō ^E�}�>�^%���>p��l�c�_�(�����P�}����V
���-��
?��K��_�e���'w�sQ'�r#h�N�~�F��6��-[���g��/7`p�07a�S���г⒋���g���x���:VSj�qFwǜ�h��w�ﯽ��ӭ@R�>�Ͼc񣎾h��u%��#MG��
G��v��w=#'O�?��E.k-j9y����-Q��=��:�����^�'�됾�7�Q�n���_[��nՂ�N	n7��������ݿ��\��\��\��\���M\�[��t��GI��!�����]A�z��R�[��W��|��;�q�����|��4�2 �i9���N�����]�T����#���4�C�hSm���^����kHa��'���!���ڳ�ArFy%�o���	E���R'���&"�@�+6�P�1q
W�$�/K����I�8�K�w���݂�;ͻ_������lM��č&6z뚧�ј_�O�����~h=R�{���D�N����3U��K\&K"vN�ka��Y�E�׫���+���i��X^�Xgn�Bܼ!�>��Z�[�՘}�C�����}����>R �7��Wme�'���b1K��#0�|�)�뱆���U~������X�������R���oIRV9w8z&ghG�IpK,�4&�Eh�������Q��ɡ&q,�d����t80},�,|v������"$�`λz����F�$t!�E0��9r��m������,ӫf�}����b<I/a7(��p�����_U ���E�EE`�m]��m
�%�GH󻸣����^s���9+�6ؖ�C6$��=��Cv"�L�֮�����֭K��1�(�7�55��~aF_�L���#�����K#�.qJ����P���
�	�=|C��b�-���ڟ1G�J�8��j��0ҔS���pu��\�j���iңd��U=V�H/8�X��2⾍q�^�z1���Z��51y���6�O0f�>Q0;�Y,�PO ;I�Sr��   ��W Մrzx#�~�5����W������L�*�:{S��XA���nSnిU��U-,WM��Z�du2�ts@fZ�N�f{0uח
xH<Xk�o���p�|��k�X�ʌ���S�b��_�1���@3�
#E���~�!�nؾr,���V�V�`�Z�hY�>9��w��j�*	H
�c�2����9��H��ݣ@-&�K�1A�t�ٺ���~ C�Q�#&��,ᶰ��~��j����B���*��L�)�}N�2�p�ph1��%���#���D>T�>��J���T�Ī{��ZݓK�.fR����P��I��>������}4ҕi�vs;��A�*fP1��T̠b3���*&�]fO�R(�����z�F��u���$���NQw��;��[bo|�=i���q�~R%�����Ġ%-1h�AKZb��-Q���^U����W{�cP�C��<�NGtQ(R.x �51����S}��Q��"��(U�bYEH�GJ�ℓ.qU�H���4Q�P>Q5ՔԨY]��Z)$q��a_^��nJ���lh�K��֯��T�:�9��Au�sP�;��ODk֞�M菖�
��`�e	f�B�*30 ���E�]�˩����A����E`�nL
ƾ���=�>c�ԧ�w���e����'a[x��x��j]�<ԫ�/h�T]^�`y��`y��`y��`y��`yN���N�`��`�x��-5ŗ%�&��Ü\��uCŃ	�Zz�҃�����-=h�AK拉?@=�� '=|�-�W�vס;(��HKT�qY�ּ�(��eUQ�)�w���x�*j����f%2(�A�JdP"��ȠDvR"��w�d��>%/o�.�v�k�/�t��O�?��4+��)�E{67)��sL�B�2{E�q�=�j�Vh�j ֻ�v���-F��
z�ahLA9�_"���l�ߡ@�ڮZo�c��:ש~@Bl�Q��,�%��^W�~�ru�t��D����K�y>Y_+����}�|2E��ݻ�i�TѿG[��������E��+_���Ѻ��(x}�4��Ơ���=�O�T��r6§�6�H���s�>a]�{���u�dX����p(\u4�j�\��6��%Wk��a�cKF���=�m�Ȉ��bG74�
���lA�Y��/S��O���c��iG�!óz�C�W&Č\�8�ת�}H.KSsV��`ęN�θ�w���Ǩ�m��[ kik����J��	v����BA+|��0#�/��4��c���J��"�B�+�z�!Djq��Um?Q�����)�+L�������(�����o��lmz�7���-C�ݾ�����>�0�����֣�u�5-�]˾��eO|I���ͦ�zg{f��� �������-p	�_UQz��V�K�xϱ����s��4UdDX�T��2]���J�v�5��8��vۚH�Vj���]joL����)��Ⱦ��c��ȶp�`�k�������xo�.�, _@1��O��1l�̉A\"|K����u���oP�E憆>E�E� 8O��� /g��DdĖ�3�g����d���$_�yy�\\�Xqz�@3���tf�ڐ]��r��_��_�?��*�      �   �   x�U�;1E��Y��|JJ�@�b��Yx.s47�(���r�����h�����V_ry�~�a�ٶd&ٗX��ww�{�d 苵^��p�&���e6�xP�2���(��51������.�i���<�+��~E7 7�غ���|������V|m�&x�p�C��Y��� 
��R��'��      �   .   x�3�4B��̲TNC.#NC �s�9�\#.N� \6F��� ��      �     x��S�J�@='_1�P����-D�����)��&�v�v&� �w�I�Kr���{;�&�AH���k�%� �JA��!1�j�B3��ʲ��0*�� ��	,Y�K��q���6��!$���F���u����-VƲ���Z�m9<�$[V��d�~eL��v5#rN�y�e�y/�R$�FC\�<Hn.T�x2[Xn���%�V��߂VHb|����͙��M��}�Y�7Q�a�a�Q�,�|��ߝ�ϼgA���w�?g��0���O�x���^o}����V�      �   C   x�3�tN,NUpI-I��)���2�-N-RpL.�,�,�TJ-�/*)&I�˘3$�8n(nW� ��4�      �      x������ � �      �   '  x��]mo�8���
"8Z�]�ym�_Λ4hI����8��"Ѷ������A��~��zʎ'N�~(qf893���s�$��R��8�rM#s�#yuB�4��3§��qLCN.Xȧ�;}�vY0
����l'.������I�ȯ�ߐ2��f3��菳��E��T}��}Э�R|hb�>�`�{M29;i5��'S$��f�9)�T�5�Jڈ�?0� �M�є��9�ys\�H~5�Vd>��Q�d!>EY�W��0QA��
�� phl���c�
T�>b��y��y��)�ʦ[�ތz�7��Wt��=���%�}����r�5�{��ed����������ӄ�X�&���(D�����t�9��	�%9q�.�Ep�������{L��҄S��:k6h0gG����ӯuw���4!)��ꆉĵ���ܩN3u�X�*�@�)���P�!���j�uc�U��Q3/��m��q]��(�	[$��g���;��j�B��	��Ǳ�ް�Xl�7��c�)�������;���4d|?�C����&�_�����u�4nI��qG�6$)@y��η�ȉ����	�r��zB�{���)��R���8f�\��p�0"�=��J���'HK�)�G�1�|.�ܹ�B��S_�Bu8k��%��H�!�z|�����4�f�ں;;�m�{G%~����錷�u�N��S��Y�]�RɡQ��]7�ܰJn����C��OvcJT8�-��3��Q��CA�wЄ\8�\���;��*MJV�y�vk�dǳ0J�2#��x,IW��!���1KC�A�,�O��Y�S�c^a(���S���Fge��F=����������
�㵃^<ș0�^�=�������~�O��D,�V�!�56
�c,�d9���5e��e)jkJ[S����V�y���%��a^a���?��Y��M>�&���ܻ�����Z�8��⼏�n`"�)FO~SMH]ߺ��!
���(�?�� �2�((������
PaO��1<c�`n�u��l�`Ϣl�`[8ث)����� ~�
�=T����M�=I���-$�}qr0ew~8!(M�8�A���Sh1,��M`�R՟!�P�x��0�������>��S���:�ÔS�6�@P�����V
��ߐ�g��{���]3;:�q�?��u.ܽ杇��?B�H��t`Q�'}��Yv#nc�Qf��uO,���Np�o��y���4���(�d� ���oj��LQ#�fE^F8�*���1�g�_��V�a�eް���N_�{0��#�p�ؤ�Nw_�\�(�݉x��D`��X|��+_ٶ���W,�b���X|��+?/�"nuv�:�z8!NB`[ ���$fi�t�5�]�T�͜	�rt�N�5��Z��Rk\3���G�o��p�~��%��8���bL�Ttng��7S,W)x�����f|�s!��v'��l��"U%���l.I�J%��:�$��4�[HԎ�7a�ڂi���J؍ܧ�d)1Py�%eTd��VO	eP�i�aqa����)�P�*�!���и26�t^�3�lQ=E�'���+E��dCH.�A�rY�3144������-�h�C��aZ@2�BJ�`���h�HI�HIn-�h-�l���&�-P�e�֤{�M0GQ���CM	[�2������^�����)4��o���������^�j?0��z�މ)�9��
����*z�7��Mi�
���U���rk���j,��AwP���$���6�I�^>M��Q��g�ۭ���0��	��r:��Pk�=�pi��'UO���2��W4�єZ�fcV�|bs:�4�T�](A�u��}EED���2Y#��z�i��z>��6�٘��1���Vq�օ��8Ї���w������SQ��t{��]��^������R}�B�kC��7 U���}�5}^�M�9����;��q���.���~ͺ�D�+��Io1��S�'s���2`���u��K����u�V�H�ᘣG'0�ؿ�G�MM-��U�ѥ`�:0��;F�WhZ�G�P�Bׅ�6��>��5�}Qpꎪ���bA 5P�`K_������=���V����b�p����	2^����7�����ʓ�H�m��_ D"�eZ:/h�k>���v��F�lZ�G�b従q����􃀹NA�#���~��粂xϿ�WM�|������V���iQ�ӃR���H!0+�� \J~}R�	K)7����ɐԳ�������³p���~8�~?�� 0����1���?+6�o����VO�i�� �7��	C����ۏ�5-����I����^�{���+���jO/�^�L�P x�_�W�$�'!��k��H:�}Ad_�D
O�/��"��Ⱦ �/��l�Q5�x�DU±C`qd��TP���Q��$7IQH�{e5�IE�2�p�-	�˪F�U�*�p�d^�4}2/h���sj�8w�SW��8seyK�Zh��i+�j����%D)�,f�R1ӻ�J���$���4��Q�����A�9ܝ�?��!{�Br�!�؅�aU���"{�[3����\���Y�3�����'����\(vj����G�<���= ���������X���+�<����=�S}�=p�U�|�!�R�NqMc(<�|���g&4�Q�M0���T��o�= �B��RDv�۝�`�(J��^P>m}Y�`Ke���t���=�����9�$���t;|�?�lmm��s�      �      x������ � �      �      x������ � �      �      x������ � �      �   (  x��[ێ�8}V�_b'o�!4蘱U�%�$'�|���{�}l
u3R:�D^�24�.��������Ҝ�
_ۦ���Zw�wM�g�N�6�|vx�	߫F~�
O����}���X���~&�b*ߧ�������z��8,�?��p@�"���;O��nz�B���N�`�u��[cX��E�9Uߏ��0Fkh��b,�)�?����[,�z��'��?ҙ��������S�͐8�%�A�8����Ƈ�1��8��<��v���ImSW��3�y�+-T��MU'3�������T���l"�ޑ��U�Ny�v�}�K����D��Rf~f=���^��N�fO˓顝���kg;P
�F=��4��y��¤���lL�� =����_L��BvK.&]R��ƕ}e�a�{.y�����3ĥe�gH�2	���L����W�\�A�%��x�)3�1.��3�A� ��h��Ge��)�,�K�יcm��F����!�`�k��}*�]L�!Nц��>Gm��yEX���ף��d�m�vg�{�����-4�py��ﮩ���6��C��lL��c�d��ԋ}Mk�)�,G��C�,�T��hGu�m������=.�ʘ�	nqE�_�yRf��cY�mvO��AB�X�b�,�^�u�ړ�/��\8���Iy�m�pM�пc�mm�{��H�>v�/ڀ� 
�]E]+i��G��<>��(g���^�A�2\g��B+M���
��ðw�=�DB�.'Z�p�&����'�}�F�M�*g,�_���6Z�Ur�� ���o8�2fm�|�di��\��,	�~-\��G�_��Yn��;���BK~JAE�ϝ�\>D�[�]�Ͻ���	
q ؍2���ד5Q��b�|=ԡ���m�2\w�%��z]�ʄ!���~�]m^R���M�X^��k�w�y��c�������֬�6{���>Գ���Y�ߢ�����I�t�R��lR�p�.���N�4��(J�a��S��ҟ��!9.�5?�^���̖\�I��.s�D��B��f�
v DT�=�����e"�@=�!S<�#d�&1U��{!�Tx��Wߙ�[�ڸ��J>�!��Q0��ټĬ�W�/���-,Q�U�_MMH#�����.'C�s@"ձ>�(b������"YΰgI�[!H����pq�)?
���k�{_��n��0iZ��l�T�Jv������E��I��(ܜ�tHod���a���q�E�����N�I�L.W�����y���_NfP|�V�^������z����pfJE�f��y���)�t^O8][�Eo�󗅱�q��dUgef0o3��՛!~�eH�*�xEx����(�Hq��z4~=j�`8��3�8�s:}MF�a�����3��T}���+��9au������g1�Sc^��S��>�aj��H|f�;����=�3���x;��:ufA�=z@�C�4)��&���(�`OQ���i�dX�2K�V�Ʈ�I^�М8=}�g1ÒeFM�2Cr�h�ѓ�ۻUUQ����K\���j��ō<%��]�<[#_�p�Q���=���e�H���6=���R����@Ίb���W��!*�Ū>� ��p�ˊGW�;v�S�g����r��|JIcQ4�\�?I��{j�D`;��Mj3������fN/o��dD�3cL��Nq<��zP�y~N��Kՙ�1��.�LA)]��U�Q�SW�	FA�s,oE�J�-�	\�xƢȰM:O�&|ȿ�hv��J�@8D�ȍQ�lV5-��cWҴKYӇ���$��p-xW�����?#in`      �      x������ � �      �   `   x�U���0D��cLi����p3���&�ƻG�Q������
h��Bˇ�0�S���p��&�sr�yWK�&�V:��`\p_D�8�7P      �      x������ � �      �      x������ � �      �      x������ � �      �   C  x��]mo�8���
�w(�ma�%q.�a���.nr����z0h���J�V/iݢ��HJ��B˒�ز3] k�MI���=��0�7��.�k{��5��������,ϕR�K�jto!�������������-O�[�]��^���6n�Cn���M���~����h��tNˉ������]}������q�7�C���e�����J���	>vi���8,c�׉�.t��<�j:C�ˊUd="�z~e��zn�^�7�8�[M������=�NZ�q�7�uT��tL�!r�:E;*��3/[�A�/����.�I+���ߺ�6����#2h��twb��CY򈳌��&z��9Ĝ�&�|�v��˻YZ��U�&���n4����^;4�lL�w���:�J�H���߶�mL���=�'��NLd��Ɋ��ak�xάܘ�Q���UwB�٬�Y�k��m��t���������G���.~�������w/�R�a9*ᵪ��e�P�nbz͟t�{Tty��+��3��[�k�NT��~� n�c� �b�,�j8)l�h����8]U�]��R%����%6m�,1��+��ol��`�|Uhbs�w�۲峏�*lR<I4V�At a�����DU6�>�˩2WO����W��9KY�tOg���RO�������8�ф��DiE��z���1t}��U�?_��{[�]�j������B�~=�~&�	^�v%]��`�z����ȏ��� �V0!br�b����G��ҟ/:}i��/����J.�1Ff�x�����	��@U�o"n�7�W ���	��V�f~�VEw3�����Ԝ8�x�"WM�.��](xtr�@�
�$ġB����k#�Ȫ~&"xH��Z�d�2s%�-B��'#y�ׁ^�M�Sj�лmiHL�X}S~0�%�Pip�)yR�D&3y����uΟ��R�[t
ׄ�#u�M�ˮ���6���p�qhN �
�ù�L����f���|ޅuIt�h��9����T� F�p��r��v���eZ�+<�9�s�F}>�:��]�-OEzp�Y�].-)I�^�E|�dtw���-ӄJy��E��%{��� ���ۏ�z�N�p��<!~���������O4��=&[�1��@/�_/��3�{����Q�3Fs��K6��=�D�;��F����b��8��}�'�0S$�e���E����@��:n]ߏ���V-L�F��62YWѝ������7����!}���Uݚ����Ƅ�FvT���"	����.�$y�r�q���ݴܟ��f����gV�������`�y=N_��	#m��k�k�L��03�#R
3�6`f��n�JPh A�pp�s-�?_t�{�hP#fgp �4!``�:LRx�&;a����sK~����w�(���
�MZMۣ���q�k�,�������9b���tn ��Ȥ��L��Ũ��f�7�s�hkk4N�ާ��oR4���e�<c���k��n��O�*�����T��~�-<�=�}	�h������b;9�W���0��(�I|�O4�K�⾈� ���_��$q5U5<��L� T׹�A��G�#0/:���9r��F�&��Ŭ�f����tM(Z!��.��y�I������/�Mc�W��Ra���G�R+J�@��C�eA驸Yl�Mn�&��a�O;�ª��xk�J)��E���s!i�6���V��	D�%�}��M�ϐ�0� ��K�Jnw��PBp�Cr��8 ��U�#���8��`Dmy���b��*�#��۸��w 	�W��@����Y�� ���z�rv�X`8����t.��ɝ.@�u�)�d"�O$�࿘��ۑF������4�O�"�Tr��D�N�s]�,ƃyq.rV��Yfݾtw�;F�Ä 3�^�d�
d���PJ[�Y����s%JiwJ��sX�R�J��PΤkj,��Z*��6����?V4+v�r�-b�]�����>k�L��(G�]���'E�1lYB�*��׼s�7���X�%eC���#���Gwu��H$#�ˆX���D/rђ�ݓ�a��\�/ �n�X�*�O���\��E�J;G�>jÇs��.tl�R�l�D��)�@$�kC)� � ��,e���C.���
���?��C>�ŪL��ޅ4"��b�/q��|O �9�}g�
�+g�ݝ�L�hN�Pv�����W77����D���uɡ�=�b��t���(���Ea�=�U*S9t)�Q�E�!����/r$}�:-a���
�\���){��o�jjIQC/v��O1,��4��
��>�(fTrPɫ��9)�%����gDU8d�ޓ����cpy@\?3�r䬢�d$-z��`+��z�n˵�ޡ٢9� �X{`�/�/��T��:J*5F�4��9��1�B;:�	;�!-pȓ��ȉ�.���;��:�C���!�W�9,]�e��dL�
{���K�C�j5�[�psD(/U��	��0n���ͬ�=p�Wz��|��Za��F<��]a�|u����tE����.�o�1�k������J��
T�؃��i�y�O�I�D�D�D�DN�D��,{?�}���r읒��zm�ӭ<�&��� \Ҝ�◕�sI���'��G����ܯ���|H��)'esDۅ$i o�6�Ld����*h��&��T�C/K׻� g=�;.'k�eS�`�os�Щ)9]�|+�^-*P�mEǂ',��oS��2�K2�ž����H�9���B����������K��O��5�I7�)�U:�p� J��.�\}��a �b��遳CU��L�W.����!��{��z��r����gN��^Wz���a�|ٚ���E�p�"%���Z	,��U�Ԙ��n�$�j�h�#�`�ej��L(������<�p��e�z�A��qL6N�s|d=�PY��)�:ĢF�bi:W��9��R�Fi���r�ʔ��:.&�LP��N	�f���jCQ)/#�B5�O?W;n]ߏ���V-��F��62YWѭ�o3|��.����]���I^wk�	�������߼4S���4!����8���?H�z_e�/w���R����ד���2���Z%p�l���t?P@�8PQ|���wv�w�(Um��������x�@LALCWu�a<���ɩ�U�R�9)���b"Y�J+;a�<vG�W�jÃ	_��s�����eP�,�G��E��dKw���-����O���Vs�k�YB����S���=��I���Z��3�����LB)0���|��:���ѻ��r���%��t��tU�>'"�1�Ih�C��Nջ�����5d��N�d�;�Ԉ?_X�WA��S�3Sn�nlr�ns�s�O�!��d�;A�@�����(�([`��=���s 1 $ܤ� �P�qSc�(���6u�j�?�?�?�?�?�?��?�R�Ɵ�d�z��)�=͍.ΡE"��2bD���*�ò���j�&�q�q�q��gA�y�-sWY�L���VWgs�n[Gu@�@�@�@�@�OM�9���t����/�%¼�      �   �  x��[o�8���WDhzWU=�j�B�AˡvfG��(%�X��Qt������@K�_Z�����������vU�٘!�@�������a�N����JC7��7]��ڄ�A�O�����<�D_2�+���+��ӿgG��Ï������ �c��f�V���PAi�
��,dw�MM�)>�Zz���ݧ����>k�_z�R���O�mM{ҏ���4OW�hؠ�.��C�l����顴\���eB,'�w2	��d��� �9u]3��:�P�ũ��PxR��6��t�����i=��x���Et&�c��"uzs�$)Rd�?��`��:�/���ҳ���=T��G�=`��dC�`�s��'�-.9U��PC��h�/�*wi�J�)vŚ�c�X0|��&��u�`���QX�
��G��3��$�ʔ	(�X��;l��B�|B�c�Bb��Jy��j�~�����Z�z4�A�����&�6#�a�rCX8���M��2�O��>D%�?a[75lO��cb����XM�,��Y:*\_��(��E~J�7ns �Qtٱ�}��F�qd!O���٪-n��"����话�h��� ��|��X˸��H:ըYà#��.�}�d2J3������A�^�o�� F��7z}����9���� �E���k���6[xQ]Zb���KҬ��0[��$�
+1	���LҬ�2�0[��$�
+5	�(6�hPuR�
v�X�7}��DΌ�H�LJ](>���,~�Z%,N�i�b�з���e�x5e���Q��l-�'�,X�n��������:̽-���7�$��V�Ŕ������{�K蔑�9NJ��5��X��;V�2ڪ:#l��e�:��^8�tJ�Jχ�SZ�W�˨����^x�aG�o>hcW�=::i��<��f��>����z��]�'n�KZ\SX	��y~~}~�9"���qG�ސ:�#�5� �Ik�	;M�����C-�hB\#l��{v���W.�iB�)~
�?������?cF_{!�"x�v^+c�V ��eNf-A�If��t%��JAk���푼wl�`�­e>	�Ip�א?�j��\˘�]��D׎����S0ص��	�Ix���ks@�k�^�����$�&�7K�e]J|M�k_��Z�_˨?��b��q谻��W綫6Y�� 
(6���g��>%T�TH!�(��ۇI�Ȏz@�~�|;�N���ާ�ч����.O31���[���W�yv|��:u��c� �u� ;n�$E@'���V��y�t�֊$J���ܧ�U��z���l��3n�	X�U����݃��fB���(pK,��rTU�l˧��q���v���
�&�kWe-� ��uW��\v��9u��'鶩[0�AH�5���&3d���T�64@�ZNR��.�v=�*V�U���60��R�J tY &�e|S�2�� ?��ЫLN���&U�|/fq�\a��P��ـ�D%��r���Q'*��H�d6�=Q�T�ߓϺW�x	��2�d��e�ֈLZ\:X'2�kq�T`�Ȅ�ťS���}lF����h'�Y��A/�O��J[Ta��9H�{�V�#�RHrQ�oDl��T�RFP����ٜ7����2�C��Q=�ɯqҿ��~���4�]�s�[��k8�{8�#Z�
q��Y<�ϛԪ"o�x����?DuG1i�������\+����1�ǧ�[ݎ���e�7����n����?Ѵ���a8t�ׁ�P9���.Q��R9o^�P9{(w�뚿�w����#�뼥G��r��uXצ݅d��L��<��5���Z�6�k�[o��n�Uډ=�}����?��q�͸c���~���[���p�4�(2�7�$#yk�[K�Z��B��[C`	��JU+IxK�[ޒ������s�%�:��:�<�������>�5@籓��x�0�Rp����/ ��u�qN�	�?����t�gS�k.b�Ӿ�Pm�}�n0T��W���\9�?��m�F�֠�S�-��g~"C|.y*�~�ގ��=��P����B� ;�A֯Os ��׸f\��}�Ŭ�M��=��gcs��iK
�*�˖
9ӊ�>��96�T㜓 EC��ضH�:>�O�W�D�����okڐ�M�?�6�}��1�¦٣�t�˥��T�=:���i�g���j�r��sV���O��k      �      x������ � �      �      x������ � �      �      x������ � �     