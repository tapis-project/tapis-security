/*
 * This file is generated by jOOQ.
 */
package edu.utexas.tacc.tapis.systems.gen.jooq.tables;


import com.google.gson.JsonElement;

import edu.utexas.tacc.tapis.systems.dao.JSONBToJsonElementBinding;
import edu.utexas.tacc.tapis.systems.gen.jooq.Indexes;
import edu.utexas.tacc.tapis.systems.gen.jooq.Keys;
import edu.utexas.tacc.tapis.systems.gen.jooq.TapisSys;
import edu.utexas.tacc.tapis.systems.gen.jooq.tables.records.SystemsRecord;
import edu.utexas.tacc.tapis.systems.model.TSystem.AccessMethod;
import edu.utexas.tacc.tapis.systems.model.TSystem.SystemType;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;

import org.jooq.Field;
import org.jooq.ForeignKey;
import org.jooq.Identity;
import org.jooq.Index;
import org.jooq.Name;
import org.jooq.Record;
import org.jooq.Schema;
import org.jooq.Table;
import org.jooq.TableField;
import org.jooq.TableOptions;
import org.jooq.UniqueKey;
import org.jooq.impl.DSL;
import org.jooq.impl.TableImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes" })
public class Systems extends TableImpl<SystemsRecord> {

    private static final long serialVersionUID = 1291300292;

    /**
     * The reference instance of <code>tapis_sys.systems</code>
     */
    public static final Systems SYSTEMS = new Systems();

    /**
     * The class holding records for this type
     */
    @Override
    public Class<SystemsRecord> getRecordType() {
        return SystemsRecord.class;
    }

    /**
     * The column <code>tapis_sys.systems.id</code>. System id
     */
    public final TableField<SystemsRecord, Integer> ID = createField(DSL.name("id"), org.jooq.impl.SQLDataType.INTEGER.nullable(false).defaultValue(org.jooq.impl.DSL.field("nextval('systems_id_seq'::regclass)", org.jooq.impl.SQLDataType.INTEGER)), this, "System id");

    /**
     * The column <code>tapis_sys.systems.tenant</code>. Tenant name associated with system
     */
    public final TableField<SystemsRecord, String> TENANT = createField(DSL.name("tenant"), org.jooq.impl.SQLDataType.VARCHAR(24).nullable(false), this, "Tenant name associated with system");

    /**
     * The column <code>tapis_sys.systems.name</code>. Unique name for the system
     */
    public final TableField<SystemsRecord, String> NAME = createField(DSL.name("name"), org.jooq.impl.SQLDataType.VARCHAR(256).nullable(false), this, "Unique name for the system");

    /**
     * The column <code>tapis_sys.systems.description</code>. System description
     */
    public final TableField<SystemsRecord, String> DESCRIPTION = createField(DSL.name("description"), org.jooq.impl.SQLDataType.VARCHAR(2048), this, "System description");

    /**
     * The column <code>tapis_sys.systems.system_type</code>. Type of system
     */
    public final TableField<SystemsRecord, SystemType> SYSTEM_TYPE = createField(DSL.name("system_type"), org.jooq.impl.SQLDataType.VARCHAR.nullable(false).asEnumDataType(edu.utexas.tacc.tapis.systems.gen.jooq.enums.SystemTypeType.class), this, "Type of system", new org.jooq.impl.EnumConverter<edu.utexas.tacc.tapis.systems.gen.jooq.enums.SystemTypeType, edu.utexas.tacc.tapis.systems.model.TSystem.SystemType>(edu.utexas.tacc.tapis.systems.gen.jooq.enums.SystemTypeType.class, edu.utexas.tacc.tapis.systems.model.TSystem.SystemType.class));

    /**
     * The column <code>tapis_sys.systems.owner</code>. User name of system owner
     */
    public final TableField<SystemsRecord, String> OWNER = createField(DSL.name("owner"), org.jooq.impl.SQLDataType.VARCHAR(60).nullable(false), this, "User name of system owner");

    /**
     * The column <code>tapis_sys.systems.host</code>. System host name or ip address
     */
    public final TableField<SystemsRecord, String> HOST = createField(DSL.name("host"), org.jooq.impl.SQLDataType.VARCHAR(256).nullable(false), this, "System host name or ip address");

    /**
     * The column <code>tapis_sys.systems.enabled</code>. Indicates if system is currently active and available for use
     */
    public final TableField<SystemsRecord, Boolean> ENABLED = createField(DSL.name("enabled"), org.jooq.impl.SQLDataType.BOOLEAN.nullable(false).defaultValue(org.jooq.impl.DSL.field("true", org.jooq.impl.SQLDataType.BOOLEAN)), this, "Indicates if system is currently active and available for use");

    /**
     * The column <code>tapis_sys.systems.effective_user_id</code>. User name to use when accessing the system
     */
    public final TableField<SystemsRecord, String> EFFECTIVE_USER_ID = createField(DSL.name("effective_user_id"), org.jooq.impl.SQLDataType.VARCHAR(60).nullable(false), this, "User name to use when accessing the system");

    /**
     * The column <code>tapis_sys.systems.default_access_method</code>. Enum for how authorization is handled by default
     */
    public final TableField<SystemsRecord, AccessMethod> DEFAULT_ACCESS_METHOD = createField(DSL.name("default_access_method"), org.jooq.impl.SQLDataType.VARCHAR.nullable(false).asEnumDataType(edu.utexas.tacc.tapis.systems.gen.jooq.enums.AccessMethType.class), this, "Enum for how authorization is handled by default", new org.jooq.impl.EnumConverter<edu.utexas.tacc.tapis.systems.gen.jooq.enums.AccessMethType, edu.utexas.tacc.tapis.systems.model.TSystem.AccessMethod>(edu.utexas.tacc.tapis.systems.gen.jooq.enums.AccessMethType.class, edu.utexas.tacc.tapis.systems.model.TSystem.AccessMethod.class));

    /**
     * The column <code>tapis_sys.systems.bucket_name</code>. Name of the bucket for an S3 system
     */
    public final TableField<SystemsRecord, String> BUCKET_NAME = createField(DSL.name("bucket_name"), org.jooq.impl.SQLDataType.VARCHAR(63), this, "Name of the bucket for an S3 system");

    /**
     * The column <code>tapis_sys.systems.root_dir</code>. Name of root directory for a Unix system
     */
    public final TableField<SystemsRecord, String> ROOT_DIR = createField(DSL.name("root_dir"), org.jooq.impl.SQLDataType.VARCHAR(1024), this, "Name of root directory for a Unix system");

    /**
     * The column <code>tapis_sys.systems.transfer_methods</code>. List of supported transfer methods
     */
    public final TableField<SystemsRecord, String[]> TRANSFER_METHODS = createField(DSL.name("transfer_methods"), org.jooq.impl.SQLDataType.CLOB.getArrayDataType(), this, "List of supported transfer methods");

    /**
     * The column <code>tapis_sys.systems.port</code>. Port number used to access a system
     */
    public final TableField<SystemsRecord, Integer> PORT = createField(DSL.name("port"), org.jooq.impl.SQLDataType.INTEGER.nullable(false).defaultValue(org.jooq.impl.DSL.field("'-1'::integer", org.jooq.impl.SQLDataType.INTEGER)), this, "Port number used to access a system");

    /**
     * The column <code>tapis_sys.systems.use_proxy</code>. Indicates if system should accessed through a proxy
     */
    public final TableField<SystemsRecord, Boolean> USE_PROXY = createField(DSL.name("use_proxy"), org.jooq.impl.SQLDataType.BOOLEAN.nullable(false).defaultValue(org.jooq.impl.DSL.field("false", org.jooq.impl.SQLDataType.BOOLEAN)), this, "Indicates if system should accessed through a proxy");

    /**
     * The column <code>tapis_sys.systems.proxy_host</code>. Proxy host name or ip address
     */
    public final TableField<SystemsRecord, String> PROXY_HOST = createField(DSL.name("proxy_host"), org.jooq.impl.SQLDataType.VARCHAR(256).nullable(false).defaultValue(org.jooq.impl.DSL.field("''::character varying", org.jooq.impl.SQLDataType.VARCHAR)), this, "Proxy host name or ip address");

    /**
     * The column <code>tapis_sys.systems.proxy_port</code>. Proxy port number
     */
    public final TableField<SystemsRecord, Integer> PROXY_PORT = createField(DSL.name("proxy_port"), org.jooq.impl.SQLDataType.INTEGER.nullable(false).defaultValue(org.jooq.impl.DSL.field("'-1'::integer", org.jooq.impl.SQLDataType.INTEGER)), this, "Proxy port number");

    /**
     * The column <code>tapis_sys.systems.job_can_exec</code>. Indicates if system will be used to execute jobs
     */
    public final TableField<SystemsRecord, Boolean> JOB_CAN_EXEC = createField(DSL.name("job_can_exec"), org.jooq.impl.SQLDataType.BOOLEAN.nullable(false).defaultValue(org.jooq.impl.DSL.field("false", org.jooq.impl.SQLDataType.BOOLEAN)), this, "Indicates if system will be used to execute jobs");

    /**
     * The column <code>tapis_sys.systems.job_local_working_dir</code>. Parent directory from which a job is run and where inputs and application assets are staged
     */
    public final TableField<SystemsRecord, String> JOB_LOCAL_WORKING_DIR = createField(DSL.name("job_local_working_dir"), org.jooq.impl.SQLDataType.VARCHAR(1024), this, "Parent directory from which a job is run and where inputs and application assets are staged");

    /**
     * The column <code>tapis_sys.systems.job_local_archive_dir</code>. Parent directory used for archiving job output files
     */
    public final TableField<SystemsRecord, String> JOB_LOCAL_ARCHIVE_DIR = createField(DSL.name("job_local_archive_dir"), org.jooq.impl.SQLDataType.VARCHAR(1024), this, "Parent directory used for archiving job output files");

    /**
     * The column <code>tapis_sys.systems.job_remote_archive_system</code>. Remote system on which job output files will be archived
     */
    public final TableField<SystemsRecord, String> JOB_REMOTE_ARCHIVE_SYSTEM = createField(DSL.name("job_remote_archive_system"), org.jooq.impl.SQLDataType.VARCHAR(256), this, "Remote system on which job output files will be archived");

    /**
     * The column <code>tapis_sys.systems.job_remote_archive_dir</code>. Parent directory used for archiving job output files on a remote system
     */
    public final TableField<SystemsRecord, String> JOB_REMOTE_ARCHIVE_DIR = createField(DSL.name("job_remote_archive_dir"), org.jooq.impl.SQLDataType.VARCHAR(1024), this, "Parent directory used for archiving job output files on a remote system");

    /**
     * The column <code>tapis_sys.systems.tags</code>. Tags for user supplied key:value pairs
     */
    public final TableField<SystemsRecord, String[]> TAGS = createField(DSL.name("tags"), org.jooq.impl.SQLDataType.CLOB.getArrayDataType(), this, "Tags for user supplied key:value pairs");

    /**
     * The column <code>tapis_sys.systems.notes_jsonb</code>. Notes for general information stored as JSON
     */
    public final TableField<SystemsRecord, JsonElement> NOTES_JSONB = createField(DSL.name("notes_jsonb"), org.jooq.impl.SQLDataType.JSONB.nullable(false), this, "Notes for general information stored as JSON", new JSONBToJsonElementBinding());

    /**
     * The column <code>tapis_sys.systems.deleted</code>. Indicates if system has been soft deleted
     */
    public final TableField<SystemsRecord, Boolean> DELETED = createField(DSL.name("deleted"), org.jooq.impl.SQLDataType.BOOLEAN.nullable(false).defaultValue(org.jooq.impl.DSL.field("false", org.jooq.impl.SQLDataType.BOOLEAN)), this, "Indicates if system has been soft deleted");

    /**
     * The column <code>tapis_sys.systems.created</code>. UTC time for when record was created
     */
    public final TableField<SystemsRecord, LocalDateTime> CREATED = createField(DSL.name("created"), org.jooq.impl.SQLDataType.LOCALDATETIME.nullable(false).defaultValue(org.jooq.impl.DSL.field("timezone('utc'::text, now())", org.jooq.impl.SQLDataType.LOCALDATETIME)), this, "UTC time for when record was created");

    /**
     * The column <code>tapis_sys.systems.updated</code>. UTC time for when record was last updated
     */
    public final TableField<SystemsRecord, LocalDateTime> UPDATED = createField(DSL.name("updated"), org.jooq.impl.SQLDataType.LOCALDATETIME.nullable(false).defaultValue(org.jooq.impl.DSL.field("timezone('utc'::text, now())", org.jooq.impl.SQLDataType.LOCALDATETIME)), this, "UTC time for when record was last updated");

    /**
     * Create a <code>tapis_sys.systems</code> table reference
     */
    public Systems() {
        this(DSL.name("systems"), null);
    }

    /**
     * Create an aliased <code>tapis_sys.systems</code> table reference
     */
    public Systems(String alias) {
        this(DSL.name(alias), SYSTEMS);
    }

    /**
     * Create an aliased <code>tapis_sys.systems</code> table reference
     */
    public Systems(Name alias) {
        this(alias, SYSTEMS);
    }

    private Systems(Name alias, Table<SystemsRecord> aliased) {
        this(alias, aliased, null);
    }

    private Systems(Name alias, Table<SystemsRecord> aliased, Field<?>[] parameters) {
        super(alias, null, aliased, parameters, DSL.comment(""), TableOptions.table());
    }

    public <O extends Record> Systems(Table<O> child, ForeignKey<O, SystemsRecord> key) {
        super(child, key, SYSTEMS);
    }

    @Override
    public Schema getSchema() {
        return TapisSys.TAPIS_SYS;
    }

    @Override
    public List<Index> getIndexes() {
        return Arrays.<Index>asList(Indexes.SYS_TENANT_NAME_IDX);
    }

    @Override
    public Identity<SystemsRecord, Integer> getIdentity() {
        return Keys.IDENTITY_SYSTEMS;
    }

    @Override
    public UniqueKey<SystemsRecord> getPrimaryKey() {
        return Keys.SYSTEMS_PKEY;
    }

    @Override
    public List<UniqueKey<SystemsRecord>> getKeys() {
        return Arrays.<UniqueKey<SystemsRecord>>asList(Keys.SYSTEMS_PKEY, Keys.SYSTEMS_TENANT_NAME_KEY);
    }

    @Override
    public Systems as(String alias) {
        return new Systems(DSL.name(alias), this);
    }

    @Override
    public Systems as(Name alias) {
        return new Systems(alias, this);
    }

    /**
     * Rename this table
     */
    @Override
    public Systems rename(String name) {
        return new Systems(DSL.name(name), null);
    }

    /**
     * Rename this table
     */
    @Override
    public Systems rename(Name name) {
        return new Systems(name, null);
    }
}