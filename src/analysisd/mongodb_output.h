void mongodb_output_event(Eventinfo *lf);
void mongodb_output_start(const char *conn_str, int argc, char **argv);
void mongodb_output_end();
char *Eventinfo_to_bson(Eventinfo *lf);