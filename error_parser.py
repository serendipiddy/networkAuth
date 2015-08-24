from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet

# http://stackoverflow.com/a/60211 using dicts as switches like this

'''
  A class for printing readable error messages thrown by Ryu.
  
  To use, simply pass it the error ofp_event.EventOFPErrorMsg event.
  Example method:
      @set_ev_cls(ofp_event.EventOFPErrorMsg,[HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
      def error_msg_handler(self, ev):
        ep = ErrorParser()
        error = ep.error_string(ev)
        self.logger.debug(error)
'''

class ErrorParser:
    # def error_msg_handler(self, ev):
        # msg = ev.msg
        
        # self.logger.debug('OFPErrorMsg received: type=0x%02x code=0x%02x message=%s',
                          # msg.type, msg.code, utils.hex_array(msg.data))
        
        # return "ERROR: %s" % self._error_string(msg.type, msg.code)
        
    def error_string(self, ev):
        msg = ev.msg
        # print("%s %s" % (msg.type, msg.code))
        pkt = packet.Packet(msg.data)
        type, code = self._error_string(msg.type,msg.code)
        return "ERROR: %s - %s\n%s" % (type, code, pkt)

    def _error_string(self, type, code): 
        return {
            ofproto_v1_3.OFPET_HELLO_FAILED:          self.hello_failed(code),
            ofproto_v1_3.OFPET_BAD_REQUEST:           self.bad_request(code),
            ofproto_v1_3.OFPET_BAD_ACTION:            self.bad_action(code),
            ofproto_v1_3.OFPET_BAD_INSTRUCTION:       self.bad_instruction(code),
            ofproto_v1_3.OFPET_BAD_MATCH:             self.bad_match(code),
            ofproto_v1_3.OFPET_FLOW_MOD_FAILED:       self.flow_mod_failed(code),
            ofproto_v1_3.OFPET_GROUP_MOD_FAILED:      self.group_mod_failed(code),
            ofproto_v1_3.OFPET_PORT_MOD_FAILED:       self.port_mod_failed(code),
            ofproto_v1_3.OFPET_TABLE_MOD_FAILED:      self.table_mod_failed(code),
            ofproto_v1_3.OFPET_QUEUE_OP_FAILED:       self.queue_op_failed(code),
            ofproto_v1_3.OFPET_SWITCH_CONFIG_FAILED:  self.switch_config_failed(code),
            ofproto_v1_3.OFPET_ROLE_REQUEST_FAILED:   self.role_request_failed(code),
            ofproto_v1_3.OFPET_METER_MOD_FAILED:      self.meter_mod_failed(code),
            ofproto_v1_3.OFPET_TABLE_FEATURES_FAILED: self.table_features_failed(code),
            ofproto_v1_3.OFPET_EXPERIMENTER:          self.experimenter(code)
        }.get(type,"type %d not found" % (type))

    # The error messages
        
    def hello_failed(self, code):
        type_msg = "Hello protocol failed"
        code_msg = {
            ofproto_v1_3.OFPHFC_INCOMPATIBLE: "No compatible version",
            ofproto_v1_3.OFPHFC_EPERM:        "Permissions error"
        }.get(code,"code %d not found" % (code))
        return (type_msg,code_msg)
    def bad_request(self, code):
        type_msg = "Request was not understood"
        code_msg = {
            ofproto_v1_3.OFPBRC_BAD_VERSION:               "ofp_header.version not supported",
            ofproto_v1_3.OFPBRC_BAD_TYPE:                  "ofp_header.type not supported",
            ofproto_v1_3.OFPBRC_BAD_MULTIPART:             "ofp_multipart_request.type not supported",
            ofproto_v1_3.OFPBRC_BAD_EXPERIMENTER:          "Experimenter id not supported (in ofp_experimenter_header or ofp_multipart_request or ofp_multipart_reply)",
            ofproto_v1_3.OFPBRC_BAD_EXP_TYPE:              "Experimenter type not supported",
            ofproto_v1_3.OFPBRC_EPERM:                     "Permissions error",
            ofproto_v1_3.OFPBRC_BAD_LEN:                   "Wrong request length for type",
            ofproto_v1_3.OFPBRC_BUFFER_EMPTY:              "Specified buffer has already been use",
            ofproto_v1_3.OFPBRC_BUFFER_UNKNOWN:            "Specified buffer does not exist",
            ofproto_v1_3.OFPBRC_BAD_TABLE_ID:              "Specified table-id invalid or does not exist",
            ofproto_v1_3.OFPBRC_IS_SLAVE:                  "Denied because controller is slave",
            ofproto_v1_3.OFPBRC_BAD_PORT:                  "Invalid port",
            ofproto_v1_3.OFPBRC_BAD_PACKET:                "Invalid packet in packet-out",
            ofproto_v1_3.OFPBRC_MULTIPART_BUFFER_OVERFLOW: "ofp_multipart_request overflowed the assigned buffer"
        }.get(code,"code %d not found" % (code))
        return (type_msg,code_msg)
    def bad_action(self, code):
        type_msg = "Error in action description"
        code_msg = {
            ofproto_v1_3.OFPBAC_BAD_TYPE:             "Unknown action type",
            ofproto_v1_3.OFPBAC_BAD_LEN:              "Length problem in actions",
            ofproto_v1_3.OFPBAC_BAD_EXPERIMENTER:     "Unknown experimenter id specified",
            ofproto_v1_3.OFPBAC_BAD_EXP_TYPE:         "Unknown action type for experimenter id",
            ofproto_v1_3.OFPBAC_BAD_OUT_PORT:         "Problem validating output action",
            ofproto_v1_3.OFPBAC_BAD_ARGUMENT:         "Bad action argument",
            ofproto_v1_3.OFPBAC_EPERM:                "Permissions error",
            ofproto_v1_3.OFPBAC_TOO_MANY:             "Can't handle this many actions",
            ofproto_v1_3.OFPBAC_BAD_QUEUE:            "Problem validating output queue",
            ofproto_v1_3.OFPBAC_BAD_OUT_GROUP:        "Invalid group id in forward action",
            ofproto_v1_3.OFPBAC_MATCH_INCONSISTENT:   "Action can't apply for this match, or Set-Field missing prerequisite",
            ofproto_v1_3.OFPBAC_UNSUPPORTED_ORDER:    "Action order is unsupported for the action list in an Apply-Actions instruction",
            ofproto_v1_3.OFPBAC_BAD_TAG:              "Actions uses an unsupported tag/encap",
            ofproto_v1_3.OFPBAC_BAD_SET_TYPE:         "Unsupported type in SET_FIELD action",
            ofproto_v1_3.OFPBAC_BAD_SET_LEN:          "Length problem in SET_FIELD action",
            ofproto_v1_3.OFPBAC_BAD_SET_ARGUMENT:     "Bad argument in SET_FIELD action"
        }.get(code,"code %d not found" % (code))
        return (type_msg,code_msg)
    def bad_instruction(self, code):
        type_msg = "Error in instruction list"
        code_msg = {
            ofproto_v1_3.OFPBIC_UNKNOWN_INST:         "Unknown instruction",
            ofproto_v1_3.OFPBIC_UNSUP_INST:           "Switch or table does not support the instruction",
            ofproto_v1_3.OFPBIC_BAD_TABLE_ID:         "Invalid Table-Id specified",
            ofproto_v1_3.OFPBIC_UNSUP_METADATA:       "Metadata value unsupported by datapath",
            ofproto_v1_3.OFPBIC_UNSUP_METADATA_MASK:  "Metadata mask value unsupported by datapath",
            ofproto_v1_3.OFPBIC_BAD_EXPERIMENTER:     "Unknown experimenter id specified",
            ofproto_v1_3.OFPBIC_BAD_EXP_TYPE:         "Unknown instruction for experimenter id",
            ofproto_v1_3.OFPBIC_BAD_LEN:              "Length problem in instructions",
            ofproto_v1_3.OFPBIC_EPERM:                "Permissions error"
        }.get(code,"code %d not found" % (code))
        return (type_msg,code_msg)
    def bad_match(self, code):
        type_msg = "Error in match"
        code_msg = {
            ofproto_v1_3.OFPBMC_BAD_TYPE:            "Unsupported match type specified by the match",
            ofproto_v1_3.OFPBMC_BAD_LEN:             "Length problem in math",
            ofproto_v1_3.OFPBMC_BAD_TAG:             "Match uses an unsupported tag/encap",
            ofproto_v1_3.OFPBMC_BAD_DL_ADDR_MASK:    "Unsupported datalink addr mask - switch does not support arbitrary datalink address mask",
            ofproto_v1_3.OFPBMC_BAD_NW_ADDR_MASK:    "Unsupported network addr mask - switch does not support arbitrary network address mask",
            ofproto_v1_3.OFPBMC_BAD_WILDCARDS:       "Unsupported combination of fields masked or omitted in the match",
            ofproto_v1_3.OFPBMC_BAD_FIELD:           "Unsupported field type in the match",
            ofproto_v1_3.OFPBMC_BAD_VALUE:           "Unsupported value in a match field",
            ofproto_v1_3.OFPBMC_BAD_MASK:            "Unsupported mask specified in the match",
            ofproto_v1_3.OFPBMC_BAD_PREREQ:          "A prerequisite was not met",
            ofproto_v1_3.OFPBMC_DUP_FIELD:           "A field type was duplicated",
            ofproto_v1_3.OFPBMC_EPERM:               "Permissions error"
        }.get(code,"code %d not found" % (code))
        return (type_msg,code_msg)
    def flow_mod_failed(self, code):
        type_msg = "Problem modifying flow entry"
        code_msg = {
            ofproto_v1_3.OFPFMFC_UNKNOWN:             "Unspecified error",
            ofproto_v1_3.OFPFMFC_TABLE_FULL:          "Flow not added because table was full",
            ofproto_v1_3.OFPFMFC_BAD_TABLE_ID:        "Table does not exist",
            ofproto_v1_3.OFPFMFC_OVERLAP:             "Attempted to add overlapping flow with CHECK_OVERLAP flag set",
            ofproto_v1_3.OFPFMFC_EPERM:               "Permissions error",
            ofproto_v1_3.OFPFMFC_BAD_TIMEOUT:         "Flow not added because of unsupported idle/hard time-out",
            ofproto_v1_3.OFPFMFC_BAD_COMMAND:         "Unsupported or unknown command",
            ofproto_v1_3.OFPFMFC_BAD_FLAGS:           "Unsupported or unknown flags"
        }.get(code,"code %d not found" % (code))
        return (type_msg,code_msg)
    def group_mod_failed(self, code):
        type_msg = "Problem modifying group entry"
        code_msg = {
            ofproto_v1_3.OFPGMFC_GROUP_EXISTS:           "Group exists",
            ofproto_v1_3.OFPGMFC_INVALID_GROUP:          "Invalid group",
            ofproto_v1_3.OFPGMFC_WEIGHT_UNSUPPORTED:     "Switch does not support unequal load sharing with select groups",
            ofproto_v1_3.OFPGMFC_OUT_OF_GROUPS:          "The group table is full",
            ofproto_v1_3.OFPGMFC_OUT_OF_BUCKETS:         "The maximum number of action buckets for a group has been exceeded",
            ofproto_v1_3.OFPGMFC_CHAINING_UNSUPPORTED:   "Switch does not support groups that forward to groups",
            ofproto_v1_3.OFPGMFC_WATCH_UNSUPPORTED:      "This group cannot watch the watch_port or watch_group specified",
            ofproto_v1_3.OFPGMFC_LOOP:                   "Group entry would cause a loop",
            ofproto_v1_3.OFPGMFC_UNKNOWN_GROUP:          "Group not modified because a group MODIFY attempted to modify a non-existent group",
            ofproto_v1_3.OFPGMFC_CHAINED_GROUP:          "Group not deleted because another group is forwarding to it",
            ofproto_v1_3.OFPGMFC_BAD_TYPE:               "Unsupported or unknown group type",
            ofproto_v1_3.OFPGMFC_BAD_COMMAND:            "Unsupported or unknown command",
            ofproto_v1_3.OFPGMFC_BAD_BUCKET:             "Error in bucket",
            ofproto_v1_3.OFPGMFC_BAD_WATCH:              "Error in watch port/group",
            ofproto_v1_3.OFPGMFC_EPERM:                  "Permissions error"
        }.get(code,"code %d not found" % (code))
        return (type_msg,code_msg)
    def port_mod_failed(self, code):
        type_msg = "OFPT_PORT_MOD failed"
        code_msg = {
            ofproto_v1_3.OFPPMFC_BAD_PORT:        "Specified port does not exist",
            ofproto_v1_3.OFPPMFC_BAD_HW_ADDR:     "Specified hardware address does not match the port number",
            ofproto_v1_3.OFPPMFC_BAD_CONFIG:      "Specified config is invalid",
            ofproto_v1_3.OFPPMFC_BAD_ADVERTISE:   "Specified advertise is invalid",
            ofproto_v1_3.OFPPMFC_EPERM:           "Permissions error"
        }.get(code,"code %d not found" % (code))
        return (type_msg,code_msg)
    def table_mod_failed(self, code):
        type_msg = "Table mod request failed"
        code_msg = {
            ofproto_v1_3.OFPTMFC_BAD_TABLE:       "Specified table does not exist",
            ofproto_v1_3.OFPTMFC_BAD_CONFIG:      "Specified config is invalid",
            ofproto_v1_3.OFPTMFC_EPERM:           "Permissions error"
        }.get(code,"code %d not found" % (code))
        return (type_msg,code_msg)
    def queue_op_failed(self, code):
        type_msg = "Queue operation failed"
        code_msg = {
            ofproto_v1_3.OFPQOFC_BAD_PORT:        "Invalid port (or port does not exist)",
            ofproto_v1_3.OFPQOFC_BAD_QUEUE:       "Queue does not exist",
            ofproto_v1_3.OFPQOFC_EPERM:           "Permissions error"
        }.get(code,"code %d not found" % (code))
        return (type_msg,code_msg)
    def switch_config_failed(self, code):
        type_msg = "Switch config request failed"
        code_msg = {
            ofproto_v1_3.OFPSCFC_BAD_FLAGS:       "Specified flags is invalid",
            ofproto_v1_3.OFPSCFC_BAD_LEN:         "Specified length is invalid",
            ofproto_v1_3.OFPQCFC_EPERM:           "Permissions error (deprecated). New or updated Ryu applications shall use OFPSCFC_EPERM. The variable name is a typo of in specifications before v1.3.1 (EXT-208)",
            ofproto_v1_3.OFPSCFC_EPERM:           "Permissions error"
        }.get(code,"code %d not found" % (code))
        return (type_msg,code_msg)
    def role_request_failed(self, code):
        type_msg = "Controller Role request failed"
        code_msg = {
            ofproto_v1_3.OFPRRFC_STALE:           "Stale Message: old generation_id",
            ofproto_v1_3.OFPRRFC_UNSUP:           "Controller role change unsupported",
            ofproto_v1_3.OFPRRFC_BAD_ROLE:        "Invalid role"
        }.get(code,"code %d not found" % (code))
        return (type_msg,code_msg)
    def meter_mod_failed(self, code):
        type_msg = "Error in meter"
        code_msg = {
            ofproto_v1_3.OFPMMFC_UNKNOWN:        "Unspecified error",
            ofproto_v1_3.OFPMMFC_METER_EXISTS:   "Meter not added because a Meter ADD attempted to replace an existing Meter",
            ofproto_v1_3.OFPMMFC_INVALID_METER:  "Meter not added because Meter specified is invalid",
            ofproto_v1_3.OFPMMFC_UNKNOWN_METER:  "Meter not modified because a Meter MODIFY attempted to modify a non-existent Meter",
            ofproto_v1_3.OFPMMFC_BAD_COMMAND:    "Unsupported or unknown command",
            ofproto_v1_3.OFPMMFC_BAD_FLAGS:      "Flag configuration unsupported",
            ofproto_v1_3.OFPMMFC_BAD_RATE:       "Rate unsupported",
            ofproto_v1_3.OFPMMFC_BAD_BURST:      "Burst size unsupported",
            ofproto_v1_3.OFPMMFC_BAD_BAND:       "Band unsupported",
            ofproto_v1_3.OFPMMFC_BAD_BAND_VALUE: "Band value unsupported",
            ofproto_v1_3.OFPMMFC_OUT_OF_METERS:  "No more meters available",
            ofproto_v1_3.OFPMMFC_OUT_OF_BANDS:   "The maximum number of properties for a meter has been exceeded"
        }.get(code,"code %d not found" % (code))
        return (type_msg,code_msg)
    def table_features_failed(self, code):
        type_msg = "Setting table features failed"
        code_msg = {
            ofproto_v1_3.OFPTFFC_BAD_TABLE:       "Specified table does not exist",
            ofproto_v1_3.OFPTFFC_BAD_METADATA:    "Invalid metadata mask",
            ofproto_v1_3.OFPTFFC_BAD_TYPE:        "Unknown property type",
            ofproto_v1_3.OFPTFFC_BAD_LEN:         "Length problem in properties",
            ofproto_v1_3.OFPTFFC_BAD_ARGUMENT:    "Unsupported property value",
            ofproto_v1_3.OFPTFFC_EPERM:           "Permissions error"
        }.get(code,"code %d not found" % (code))
        return (type_msg,code_msg)
    def experimenter(self, code):
        type_msg = "Experimenter Error Messages"
        code_msg = ""
        return (type_msg,code_msg)
                
