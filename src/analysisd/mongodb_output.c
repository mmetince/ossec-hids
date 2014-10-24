#ifdef MONGODB_OUTPUT

#include "shared.h"
#include "eventinfo.h"
#include "shared.h"
#include "rules.h"
#include "bson.h"
#include "mongoc.h"
#include "mongodb_output.h"

static mongoc_client_t *client;
static mongoc_collection_t *collection;

void mongodb_output_start(const char *conn_str,int argc, char **argv){	

    debug1("%s: DEBUG: Preparing MongoDB Connection", ARGV0);
    mongoc_init ();

    debug1("%s: DEBUG: Connecting to MongoDB Server", ARGV0);
    client = mongoc_client_new (conn_str);
    if (client == NULL) {
        merror("%s: Unable to connect MongoDB: %s", ARGV0, conn_str);
        return;
    }

    debug1("%s: DEBUG: Getting database and collection:", ARGV0);
    collection = mongoc_client_get_collection (client, db, collection);
    if (rc) {
        merror("%s: Unable to get database and collection: .", ARGV0);
        return;
    }

}

void mongodb_output_event(Eventinfo *lf){	
    bson_t *doc = Eventinfo_to_jsonstr(lf);
    bson_error_t error;
    if (!mongoc_collection_insert (collection, MONGOC_INSERT_NONE, doc, NULL, &error)) {
        merror ("%s: Unable to get database and collection: %s.", ARGV0, error.message);
    }
    bson_destroy(doc);
    free(error);

}

void mongodb_output_end(){	
    debug1("%s: DEBUG: Destroying MongoDB Connection", ARGV0);
    mongoc_collection_destroy (collection);
    mongoc_client_destroy (client);
}

char *Eventinfo_to_bson(Eventinfo *lf){	
	bson_t *doc;
	bson_t *rule;
	bson_t *file;
	doc = bson_new ();	

	// Rules
	bson_append_document_begin(doc, "rule", -1, rule);
    if (lf->generated_rule->level) BSON_APPEND_INT32(rule, "level", lf->generated_rule->level);
    if (lf->generated_rule->comment) BSON_APPEND_UTF8(rule, "comment", lf->generated_rule->comment);
    if (lf->generated_rule->sigid) BSON_APPEND_INT32(rule, "sigid", lf->generated_rule->sigid);
    if (lf->generated_rule->cve) BSON_APPEND_UTF8(rule, "cve", lf->generated_rule->cve);
    if (lf->generated_rule->cve) BSON_APPEND_UTF8(rule, "info", lf->generated_rule->info);
    bson_append_document_end(doc, rule);
    // Informations
    if (lf->action) BSON_APPEND_UTF8(doc, "action", lf->action);
    if (lf->srcip) BSON_APPEND_UTF8(doc, "srcip", lf->srcip);
    if (lf->srcport) BSON_APPEND_UTF8(doc, "srcport", lf->srcport);
    if (lf->srcuser) BSON_APPEND_UTF8(doc, "srcuser", lf->srcuser);
    if (lf->dstip) BSON_APPEND_UTF8(doc, "dstip", lf->dstip);
    if (lf->dstport) BSON_APPEND_UTF8(doc, "dstport", lf->dstport);
    if (lf->dstuser) BSON_APPEND_UTF8(doc, "dstuser", lf->dstuser);
    if (lf->location) BSON_APPEND_UTF8(doc, "location", lf->location);
    if (lf->full_log) BSON_APPEND_UTF8(doc, "full_log", lf->full_log);
    // Files
    bson_append_document_begin(doc,"file", -1, file);
    if (lf->filename) {    
	    BSON_APPEND_UTF8(file, "path", lf->filename);
	    if (lf->md5_before && lf->md5_after && strcmp(lf->md5_before, lf->md5_after) != 0  ) {
	        BSON_APPEND_UTF8(file,"md5_before", lf->md5_before);
	        BSON_APPEND_UTF8(file,"md5_after", lf->md5_after);
	    } 
	    if (lf->sha1_before && lf->sha1_after && !strcmp(lf->sha1_before, lf->sha1_after) != 0) {
	        BSON_APPEND_UTF8(file,"sha1_before", lf->sha1_before);
	        BSON_APPEND_UTF8(file,"sha1_after", lf->sha1_after);
	    } 
	    if (lf->owner_before && lf->owner_after && !strcmp(lf->owner_before, lf->owner_after) != 0) {
	        BSON_APPEND_UTF8(file,"owner_before", lf->owner_before);
	        BSON_APPEND_UTF8(file,"owner_after", lf->owner_after);
	    }
	    if (lf->gowner_before && lf->gowner_after && !strcmp(lf->gowner_before, lf->gowner_after) != 0 ) {
	        BSON_APPEND_UTF8(file,"gowner_before", lf->gowner_before);
	        BSON_APPEND_UTF8(file,"gowner_after", lf->gowner_after);
	    }
	    if (lf->perm_before && lf->perm_after && lf->perm_before != lf->perm_after) {
	        BSON_APPEND_UTF8(file, "perm_before", lf->perm_before);
	        BSON_APPEND_UTF8(file, "perm_after", lf->perm_after);
	    }
    }
    bson_destroy (rule);
    bson_destroy (file);
    bson_append_document_end(doc, file);
    return doc;
}
#endif
