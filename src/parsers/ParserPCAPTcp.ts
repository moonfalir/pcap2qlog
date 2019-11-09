import * as qlog from "@quictools/qlog-schema";
import {VantagePointType, IDefaultEventFieldNames, EventField} from "@quictools/qlog-schema";

export class ParserPCAPTcp {
        public clientIp_Port: string;
        public serverIp_Port: string;

        public trace: qlog.ITrace;

        constructor(private jsonTrace: any, originalFile: string) {
            const connInfo = this.getConnectionInfo() as qlog.IEventConnectionStarted;
            this.clientIp_Port = connInfo.src_ip + "_" + connInfo.src_port;
            this.serverIp_Port = connInfo.dst_ip + "_" + connInfo.dst_port;
            // FIXME: we assume now that each input file only contains a single TCP connection
            // in reality, they could potentially contain more, so we should support that in the future!
            this.trace = {
                title: "Connection 1",
                description: "Connection 1 in qlog from pcap " + originalFile,
                vantage_point: {
                    name: "pcap",
                    type: VantagePointType.network,
                    flow: VantagePointType.client, // Perspective from which the trace is made, e.g. packet_sent from flow=client means that the client has sent a packet while packet_sent from flow=server means that the server sent it.
                },
                configuration: {
                    time_offset: "0",
                    time_units: "ms",
                    original_uris: [ originalFile ],
                },
                common_fields: {
                    group_id: "", // Original destination connection id
                    protocol_type: "TCP",
                    reference_time: this.getStartTime().toString(),
                },
                event_fields: [IDefaultEventFieldNames.relative_time, IDefaultEventFieldNames.category, IDefaultEventFieldNames.event, IDefaultEventFieldNames.data],
                events: []
            };
            // First event = new connection
            this.addEvent([
                "0",
                qlog.EventCategory.connectivity,
                qlog.ConnectivityEventType.connection_started,
                connInfo,
            ]);
        }

        // Adds an event to the list of events
        public addEvent(event: EventField[]) {
            this.trace.events.push(event);
        }

        public static Parse(jsonContents:any, originalFile: string, logRawPayloads: boolean):qlog.IQLog {
            let pcapParser = new ParserPCAPTcp( jsonContents, originalFile );

            let output: qlog.IQLog;
            output = {
                qlog_version: "draft-01",
                title: "" + originalFile,
                description: "qlog converted from " + originalFile,
                traces: [pcapParser.trace]
            };

            return output;
        }

        public getStartTime(): number {
            return parseFloat(this.jsonTrace[0]['_source']['layers']['frame']['frame.time_epoch']);
        }

        public getConnectionInfo() {
            let layer_ip = this.jsonTrace[0]['_source']['layers']['ip'];
            let layer_tcp = this.jsonTrace[0]['_source']['layers']['tcp'];

            if(!layer_ip) {
                layer_ip = this.jsonTrace[0]['_source']['layers']['ipv6'];
                return {
                    ip_version: layer_ip['ipv6.version'],
                    src_ip: layer_ip['ipv6.src'],
                    dst_ip: layer_ip['ipv6.dst'],
                    protocol: "TCP",
                    src_port: layer_tcp['tcp.srcport'],
                    dst_port: layer_tcp['tcp.dstport'],
                }
            }

            return {
                ip_version: layer_ip['ip.version'],
                src_ip: layer_ip['ip.src'],
                dst_ip: layer_ip['ip.dst'],
                protocol: "TCP",
                src_port: layer_tcp['tcp.srcport'],
                dst_port: layer_tcp['tcp.dstport'],
            }
        }
}