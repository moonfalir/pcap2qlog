import * as qlog from "@quictools/qlog-schema";
import {VantagePointType, IDefaultEventFieldNames, EventField, IEventPacket, PacketType, IStreamFrame, QUICFrameTypeName, TransportEventType, EventCategory, QuicFrame, IConnectionCloseFrame} from "@quictools/qlog-schema";

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

        // Based on tcp flags it returns the packet type
        public getPacketType(jsonPacketFlags: any): PacketType {
            if (jsonPacketFlags["tcp.flags.syn"] === "1"){
                if (jsonPacketFlags["tcp.flags.ack"] === "0")
                    return PacketType.initial;
                else
                    return PacketType.handshake;
            }
            else
                return PacketType.onertt;
        }

        public static extractPayloadFrame(jsonPacket: any, parser: ParserPCAPTcp, logRawPayloads: boolean): IStreamFrame {
            return {
                frame_type: QUICFrameTypeName.stream,

                stream_id: "0",

                offset: jsonPacket["tcp.seq"],
                length: jsonPacket["tcp.len"],

                fin: jsonPacket["tcp.flags_tree"]["tcp.flags.fin"] === "1",
                raw: logRawPayloads ? jsonPacket["data"]["data.data"].replace(/:/g, '') : undefined,
            };
        }

        public static extractConnClose(jsonPacket: any, parser: ParserPCAPTcp, logRawPayloads: boolean, isError: boolean): IConnectionCloseFrame {
            return {
                frame_type: QUICFrameTypeName.connection_close,
                // TODO add no error
                error_space: isError ? qlog.ErrorSpace.transport_error : qlog.ErrorSpace.transport_error,
                error_code: 0,
                raw_error_code: 0,
                reason: "End of transfer",

                trigger_frame_type: 0
            };
        }

        public static extractQlogFrames(jsonPacket: any, parser: ParserPCAPTcp, logRawPayloads: boolean): Array<QuicFrame> {
            let frames = Array<QuicFrame>();
            // If a packet both contains an ack and data, extract data from both. If packet length is 0, only an ack will be parsed
            if (jsonPacket["len"] !== "0") {
                frames.push(ParserPCAPTcp.extractPayloadFrame(jsonPacket, parser, logRawPayloads));
            }
            // if fin bit, parse conn close
            if (jsonPacket["tcp.flags_tree"]["tcp.flags.fin"] === "1") {
                frames.push(ParserPCAPTcp.extractConnClose(jsonPacket, parser, logRawPayloads, false));
            }
            // if reset bit, parse conn error
            if (jsonPacket["tcp.flags_tree"]["tcp.flags.reset"] === "1") {
                frames.push(ParserPCAPTcp.extractConnClose(jsonPacket, parser, logRawPayloads, true));
            }/*
            //parse ack
            if (jsonPacket["tcp.flags_tree"]["tcp.flags.ack"] === "1") {
                frames.push(ParserPCAPTcp.extractPayloadFrame(jsonPacket, parser, logRawPayloads));
            }*/

            return frames;
        }

        public static Parse(jsonContents:any, originalFile: string, logRawPayloads: boolean):qlog.IQLog {
            let pcapParser = new ParserPCAPTcp( jsonContents, originalFile );

            for ( let packet of jsonContents ) {
                let frame = packet['_source']['layers']['frame'];
                let tcp = packet['_source']['layers']['tcp'];

                let time = parseFloat(frame['frame.time_epoch']);
                let time_relative: number = pcapParser.trace.common_fields !== undefined && pcapParser.trace.common_fields.reference_time !== undefined ? Math.round((time - parseFloat(pcapParser.trace.common_fields.reference_time)) * 1000) : -1;
                function extractEventsFromPacket(jsonPacket:any, ip: string, port: string) {
                    let header = {} as qlog.IPacketHeader;

                    header.version = "";
                    header.scid = jsonPacket['tcp.srcport'];
                    header.dcid = jsonPacket['tcp.dstport'];
                    header.scil = "";
                    header.dcil = "";
                    header.payload_length = parseInt(jsonPacket['tcp.len']);
                    header.packet_number = jsonPacket['tcp.seq'];
                    header.packet_size = parseInt(jsonPacket['tcp.len']) + parseInt(jsonPacket["tcp.hdr_len"]);

                    const entry: IEventPacket = {
                        packet_type: pcapParser.getPacketType(jsonPacket["tcp.flags_tree"]),
                        header: header,
                    };

                    entry.frames = ParserPCAPTcp.extractQlogFrames(jsonPacket, pcapParser, logRawPayloads);

                    const curr_Ip_Port = ip + "_" + port;
                    const transportEventType: TransportEventType = pcapParser.clientIp_Port === curr_Ip_Port ? TransportEventType.packet_sent : TransportEventType.packet_received;

                    pcapParser.addEvent([
                        time_relative.toString(),
                        EventCategory.transport,
                        transportEventType,
                        entry
                    ]);
                }
                if (tcp)
                    extractEventsFromPacket(tcp, packet['_source']['layers']['ip']['ip.src_host'], packet['_source']['layers']['tcp']['tcp.srcport']);
            }

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