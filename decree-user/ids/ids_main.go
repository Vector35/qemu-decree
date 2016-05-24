// ======================================================= //
// Network Appliance (rewritten in GO)
//
// Description:
// 		Main entry point for network appliance
//
//======================================================== //
package main

import "C"
import "fmt"

//import "bufio"
//import "log"
import "strings"
import "container/list"
import "errors"

//import "regexp"

import "os"

type NetworkFilter struct {
	filter_list   *list.List
	state         map[string]bool
	client_buffer []byte
	server_buffer []byte
	buffer_size   int
}

type Connection struct {
	name            string
	side            int
	conn_read       *os.File
	conn_write      *os.File
	pair_conn_read  *os.File
	pair_conn_write *os.File
	filter          *NetworkFilter
	read_done       chan bool
}

type IDSRule struct {
	rule_type      int
	name           string
	flush          int
	RuleOptionList *list.List
	IDSRuleList    *list.List
}

const (
	LOG_DEBUG = 1
	LOG_INFO  = 2
	LOG_WARN  = 3
	LOG_ERROR = 4
	LOG_NONE  = 5
)

var g_ruleList *list.List
var client_read_done chan bool
var client_send_done chan bool
var server_read_done chan bool
var server_send_done chan bool

func AddIDSRule(rule_type int, name string, flush int, rule_list *list.List) {

	//Log(LOG_DEBUG, "NEW RULE [%s] FLUSH=%d (possible %d,%d)", name, flush, RULE_SIDE_CLIENT, RULE_SIDE_SERVER)

	newRule := &IDSRule{rule_type, name, flush, rule_list, g_ruleList}
	g_ruleList.PushBack(*newRule)
}

func Log(level int, format string, v ...interface{}) {
	if level >= LOG_WARN {
		fmt.Fprintf(os.Stderr, format+"\n", v...)
	}
}

func (filter_data *IDSRule) RunFilter(state map[string]bool, side int, data []byte, data_offset int) ([]byte, int, error) {
	// Iterate through the options -- stopping when an option fails

	// Handle each filter option
	for filter_option := filter_data.RuleOptionList.Front(); filter_option != nil; filter_option = filter_option.Next() {
		filter_data := filter_option.Value.(RuleOptionStruct)

		switch filter_data.option_type {
		case RULE_OPTION_SIDE:
			if side == RULE_SIDE_SERVER && filter_data.value_int != RULE_SIDE_SERVER {
				return nil, 0, nil
			} else if side == RULE_SIDE_CLIENT && filter_data.value_int != RULE_SIDE_CLIENT {
				return nil, 0, nil
			}

		case RULE_OPTION_REGEX:
			// Handle regex
			raw_data := data[data_offset:]
			Log(LOG_DEBUG, "REGEX [%s] CHECKING: %s", filter_data.value_regex.String(), string(raw_data))
			match_index := filter_data.value_regex.FindIndex(raw_data)

			if match_index != nil {
				Log(LOG_INFO, "REGEX MATCH: %d -> %d", match_index[0], match_index[1])
				data_offset += match_index[1]
			} else {
				return nil, 0, nil
			}

		case RULE_OPTION_MATCH:
			raw_data := data[data_offset:]

			if filter_data.value_int > 0 {
				raw_data = raw_data[:filter_data.value_int]
			}

			offset_index := strings.Index(string(raw_data), filter_data.value_str)

			if offset_index == -1 {
				return nil, 0, nil
			}

			data_offset += offset_index

			if filter_data.value_str2 != "" {
				//data = []byte(strings.Replace(string(raw_data), filter_data.value_str, filter_data.value_str2, 1))
				if offset_index+len(filter_data.value_str2) > len(raw_data) {
					return nil, 0, errors.New("Replace in match statement -- data overrun")
				}

				data = append(data[:data_offset], append(append(raw_data[:offset_index], []byte(filter_data.value_str2)...), raw_data[offset_index+len(filter_data.value_str2):]...)...)
			}

			data_offset += len(filter_data.value_str)

			Log(LOG_INFO, "====MATCH: (%d,%d) string: %s", offset_index, data_offset, filter_data.value_str2)

		case RULE_OPTION_SKIP:
			if data_offset+filter_data.value_int > len(data) {
				return nil, 0, nil
			}

			data_offset += filter_data.value_int

		case RULE_OPTION_STATE:
			state_name := filter_data.value_str

			if filter_data.value_int == ATTRIBUTE_STATE_SET {
				Log(LOG_INFO, "STATE SET: %s", state_name)
				state[state_name] = true
			} else if filter_data.value_int == ATTRIBUTE_STATE_UNSET {
				Log(LOG_INFO, "STATE UNSET: %s", state_name)
				state[state_name] = false
			} else if filter_data.value_int == ATTRIBUTE_STATE_IS {
				if value, ok := state[state_name]; ok == true && value == true {
					Log(LOG_INFO, "STATE IS SET: %s", state_name)
				} else {
					return nil, 0, nil
				}
			} else if filter_data.value_int == ATTRIBUTE_STATE_NOT {
				if value, ok := state[state_name]; ok == false || value == false {
					Log(LOG_INFO, "STATE NOT SET: %s", state_name)
				} else {
					return nil, 0, nil
				}
			} else {
				return nil, 0, errors.New("Unknown state attribute")
			}

		default:
			return nil, 0, errors.New("Invalid filter option during evaluation")
		}
	}

	return data, data_offset, nil
}

func (c *Connection) NetworkFilter(data []byte) ([]byte, error) {

	offset := 0

	data_len := len(data)
	var scan_buffer []byte

	if c.side == RULE_SIDE_CLIENT {
		buff_len := len(c.filter.client_buffer)
		if data_len+buff_len > c.filter.buffer_size {
			// Truncate
			c.filter.client_buffer = c.filter.client_buffer[data_len:]
		}

		scan_buffer = c.filter.client_buffer
	} else if c.side == RULE_SIDE_SERVER {
		buff_len := len(c.filter.server_buffer)
		if data_len+buff_len > c.filter.buffer_size {
			// Truncate
			c.filter.server_buffer = c.filter.server_buffer[data_len:]
		}

		scan_buffer = c.filter.server_buffer
	}

	scan_buffer = append(scan_buffer, data...)

	flush_client := false
	flush_server := false

	// The offset scanned so far!
	scan_offset := 0

	// Recent match
	recent_match := list.New()

	// LOG scan buffer

	for {
		current_offset := scan_offset

		did_match := false
		// Iterate over all the filter rules
		for rule_item := c.filter.filter_list.Front(); rule_item != nil; rule_item = rule_item.Next() {
			rule_data := rule_item.Value.(IDSRule)

			new_state := make(map[string]bool, len(c.filter.state))

			for k, v := range c.filter.state {
				new_state[k] = v
			}

			offset = scan_offset

			ret, new_offset, err := rule_data.RunFilter(new_state, c.side, scan_buffer, scan_offset)

			if ret != nil && rule_data.rule_type == RULE_BLOCK {
				// Block matched
				Log(LOG_WARN, "blocking connection: %s", c.name)
				return nil, errors.New("Connection dropped")
			}

			if err != nil {
				// Error from running filter
				Log(LOG_ERROR, "Error: %s", err)
			}

			if ret == nil {
				// No matches
				Log(LOG_DEBUG, "filter did not match %s: %s ", rule_data.name, string(scan_buffer[scan_offset:]))
				scan_offset = offset
				continue
			}

			if rule_data.rule_type != RULE_ADMIT {
				// Log("MATCH! ", rule_data.name)
				recent_match.PushBack(rule_data.name)
				did_match = true
			}

			scan_buffer = ret
			scan_offset = new_offset

			if rule_data.flush != 0 {
				if rule_data.flush == RULE_SIDE_CLIENT {
					Log(LOG_DEBUG, "FLUSHING: %s SIDE CLIENT", c.name)
					flush_client = true
				} else if rule_data.flush == RULE_SIDE_SERVER {
					Log(LOG_DEBUG, "FLUSHING: %s SIDE SERVER", c.name)
					flush_server = true
				}
				scan_offset += len(scan_buffer[scan_offset:])
			}

			c.filter.state = new_state

			// a rule matched.  continued analysis should happen from the beginning of the list
			break
		}

		// match check
		if did_match == false {
			break
		}

		if current_offset == scan_offset {
			break
		}
	}

	orig_len := 0
	if c.side == RULE_SIDE_SERVER {
		orig_len = len(c.filter.server_buffer)
		c.filter.server_buffer = scan_buffer[scan_offset:]
		Log(LOG_DEBUG, "ORIG LEN: %d -- NEW LEN: %d", orig_len, len(c.filter.server_buffer))
	} else if c.side == RULE_SIDE_CLIENT {
		orig_len = len(c.filter.client_buffer)
		c.filter.client_buffer = scan_buffer[scan_offset:]
		Log(LOG_DEBUG, "ORIG LEN: %d -- NEW LEN: %d", orig_len, len(c.filter.client_buffer))
	}

	if flush_client == true {
		c.filter.client_buffer = nil
	}
	if flush_server == true {
		c.filter.server_buffer = nil
	}

	return scan_buffer[orig_len:], nil
}

func (c *Connection) Read(max_bytes_optional ...int) int {
	max_bytes := 0x1000
	if len(max_bytes_optional) > 0 {
		max_bytes = max_bytes_optional[0]
	}

	buffer := make([]byte, max_bytes)
	bytesRead, err := c.conn_read.Read(buffer)

	if err != nil {
		Log(LOG_INFO, "Read error: %s", err)
		c.Close()
		return -1
	}

	// Incoming data
	new_data := buffer[:bytesRead]

	// Log in debug mode
	Log(LOG_DEBUG, "read from %s: %s (%d bytes)", c.name, string(new_data), bytesRead)

	// Check network filter
	output_data, err := c.NetworkFilter(new_data)

	if err != nil {
		c.CloseAll()
		return -1
	}

	c.conn_write.Write([]byte(output_data))

	return bytesRead
}

func (c *Connection) Close() {
	c.conn_read.Close()
	c.conn_write.Close()
}

func (c *Connection) CloseAll() {
	c.conn_read.Close()
	c.conn_write.Close()
	c.pair_conn_read.Close()
	c.pair_conn_write.Close()
}

func ConnectionReader(c *Connection) {
	for {
		bytesRead := c.Read()

		if bytesRead == -1 {
			c.read_done <- true
			return
		}
	}
}

func IDSMain(filename string, client_read uintptr, client_write uintptr, server_read uintptr, server_write uintptr, done_pipe uintptr) {
	done := os.NewFile(done_pipe, "done pipe")

	g_ruleList = list.New()

	// Read the rules in
	ReadIDSRules(filename)

	// Create new network filter for this connection
	netFilter := &NetworkFilter{g_ruleList, nil, nil, nil, 100*1024}

	// server -> client
	server_to_client_read := os.NewFile(server_read, "server read pipe")
	server_to_client_write := os.NewFile(server_write, "server write pipe")

	// client -> server
	client_to_server_read := os.NewFile(client_read, "client read pipe")
	client_to_server_write := os.NewFile(client_write, "client write pipe")

	client_read_done := make(chan bool)
	server_read_done := make(chan bool)

	clientConnection := &Connection{"Client Listener", RULE_SIDE_CLIENT, client_to_server_read, client_to_server_write,
		server_to_client_read, server_to_client_write, netFilter, client_read_done}

	go ConnectionReader(clientConnection)

	serverConnection := &Connection{"Server Listener", RULE_SIDE_SERVER, server_to_client_read, server_to_client_write,
		client_to_server_read, client_to_server_write, netFilter, server_read_done}

	go ConnectionReader(serverConnection)

	<- client_read_done
	<- server_read_done

	done.Close()
}

//export run_ids
func run_ids(filename string, client_read uintptr, client_write uintptr, server_read uintptr, server_write uintptr, done_pipe uintptr) {
	go IDSMain(filename, client_read, client_write, server_read, server_write, done_pipe)
}

func main() {
}
