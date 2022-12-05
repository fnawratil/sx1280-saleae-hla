# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting


COMMAND_STATUS = {
    0x0: 'Reserved',
    0x1: 'Processed',
    0x2: 'Data',
    0x3: 'Timeout',
    0x4: 'Error',
    0x5: 'Failure',
    0x6: 'TX done'
}

CIRCUIT_MODE = {
    0x0: 'Reserved (0x0)',
    0x1: 'Reserved (0x1)',
    0x2: 'STDBY_RC',
    0x3: 'STDBY_XOSX',
    0x4: 'FS',
    0x5: 'RX',
    0x6: 'TX'
}

COMMAND_HEX = {
    0xC0: "GetStatus",
    0x18: "WriteRegister",
    0x19: "ReadRegister",
    0x1A: "WriteBuffer",
    0x1B: "ReadBuffer",
    0x84: "SetSleep",
    0x80: "SetStandby",
    0xC1: "SetFs",
    0x83: "SetTx",
    0x82: "SetRx",
    0x94: "SetRxDutyCycle",
    0xC5: "SetCad",
    0xD1: "SetTxContinuousWave",
    0xD2: "SetTxContinuousPreamble",
    0x8A: "SetPacketType",
    0x03: "GetPacketType",
    0x86: "SetRfFrequency",
    0x8E: "SetTxParams",
    0x88: "SetCadParams",
    0x8F: "SetBufferBaseAddress",
    0x8B: "SetModulationParams",
    0x8C: "SetPacketParams",
    0x17: "GetRxBufferStatus",
    0x1D: "GetPacketStatus",
    0x1F: "GetRssiInst",
    0x8D: "SetDioIrqParams",
    0x15: "GetIrqStatus",
    0x97: "ClrIrqStatus",
    0x96: "SetRegulatorMode",
    0xD5: "SetSaveContext",
    0x9E: "SetAutoFS",
    0x98: "SetAutoTx",
    0x9B: "SetLongPreamble",
    0x9D: "SetUartSpeed",
    0xA3: "SetRangingRole",
    0x9A: "SetAdvancedRanging"
}

COMMAND_ARGUMENTS = {
    0xC0: ['status'],
    0x18: ['address[15:8]', 'address[7:0]', 'data[0:n]'],
    0x19: ['address[15:8]', 'address[7:0]', 'data[0:n-1]'],
    0x1A: ['offset', 'data[0:n]'],
    0x1B: ['offset', 'data[0:n-1]'],
    0x84: ['sleepConfig'],
    0x80: ['standbyConfig'],
    0xC1: [],
    0x83: ['periodBase', 'periodBaseCount[15:8]', 'periodBaseCount[7:0]'],
    0x82: ['periodBase', 'periodBaseCount[15:8]', 'periodBaseCount[7:0]'],
    0x94: ['rxPeriodBase', 'rxPeriodBaseCount[15:8]', 'rxPeriodBaseCount[7:0]', 'sleepPeriodBase', 'sleepPeriodBaseCount[15:8]', 'sleepPeriodBaseCount[7:0]'],
    0xC5: [],
    0xD1: [],
    0xD2: [],
    0x8A: ['packetType'],
    0x03: [],
    0x86: ['rfFrequency[23:16]', 'rfFrequency[15:8]', 'rfFrequency[7:0]'],
    0x8E: ['power', 'rampTime'],
    0x88: ['cadSymbolNum'],
    0x8F: ['txBaseAddress', 'rxBaseAddress'],
    0x8B: ['modParam1', 'modParam2', 'modParam3'],
    0x8C: ['packetParam1', 'packetParam2', 'packetParam3', 'packetParam4', 'packetParam5', 'packetParam6', 'packetParam7'],
    0x17: [],
    0x1D: [],
    0x1F: [],
    0x8D: ['irqMask[15:8]', 'irqMask[7:0]', 'dio1Mask[15:8]', 'dio1Mask[7:0]', 'dio2Mask[15:8]', 'dio2Mask[7:0]', 'dio3Mask[15:8]', 'dio3Mask[7:0]'],
    0x15: [],
    0x97: ['irqMask[15:8]', 'irqMask[7:0]'],
    0x96: ['regulatorMode'],
    0xD5: [],
    0x9E: ['0x00: disable or 0x01: enable'],
    0x98: ['time'],
    0x9B: ['enable'],
    0x9D: ['uartSpeed'],
    0xA3: ['0x00=Slave or 0x01=Master'],
    0x9A: ['0x00: disable or 0x01: enable'],
}

COMMAND_RETURN_VALUES = {
    0xC0: ['status'],
    0x18: [],
    0x19: ['data[0:n-1]'],
    0x1A: [],
    0x1B: ['data[0:n-1]'],
    0x84: [],
    0x80: [],
    0xC1: [],
    0x83: [],
    0x82: [],
    0x94: [],
    0xC5: [],
    0xD1: [],
    0xD2: [],
    0x8A: [],
    0x03: ['packetType'],
    0x86: [],
    0x8E: [],
    0x88: [],
    0x8F: [],
    0x8B: [],
    0x8C: [],
    0x17: ['payloadLength', 'rxBufferOffset'],
    0x1D: ['packetStatus[39:32]', 'packetStatus[31:24]', 'packetStatus[23:16]', 'packetStatus[15:8]', 'packetStatus[7:0]'],
    0x1F: ['rssiInst'],
    0x8D: [],
    0x15: ['irqStatus[15:8]', 'irqStatus[7:0]'],
    0x97: [],
    0x96: [],
    0xD5: [],
    0x9E: [],
    0x98: [],
    0x9B: [],
    0x9D: [],
    0xA3: [],
    0x9A: [],
}


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):

    in_transaction = False
    frames = []

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'command': {
            'format': 'CMD: {{data.text}}'
        },
        'status': {
            'format': 'STATUS: {{data.text}}'
        },
        'arg': {
            'format': 'ARG: {{data.text}}'
        },
        'ret': {
            'format': 'RET: {{data.text}}'
        }
    }

    selected_output = ChoicesSetting(['Transaction Name', 'MISO Frames', 'MOSI Frames'])

    def get_command_value(self):
        first_frame = self.frames[0]
        first_mosi = first_frame.data['mosi']
        return first_mosi[0]

    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''

        if frame.type == 'enable':
            in_transaction = True
            print('Entering Transaction')
            self.frames = []
            return

        if frame.type == 'disable':
            in_transaction = False
            print('Exiting Transaction')
            if len(self.frames) > 0 and self.selected_output == 'Transaction Name':
                command_name = COMMAND_HEX[self.get_command_value()]
                analyzer_frame = AnalyzerFrame('command', self.frames[0].start_time, self.frames[-1].end_time, {
                    'text': command_name
                })
                return analyzer_frame


        if frame.type != 'result':
            print(f'Unknown frame type {frame.type}')
            return

        self.frames.append(frame)

        command = self.get_command_value()
        args = COMMAND_ARGUMENTS[command]
        rets = COMMAND_RETURN_VALUES[command]
        frame_index = len(self.frames) - 1

        if self.selected_output == 'MOSI Frames':
            if len(self.frames) == 1:
                return AnalyzerFrame('command', frame.start_time, frame.end_time, {
                    'text': COMMAND_HEX[command]
                })
            elif frame_index <= len(args):
                arg = args[frame_index - 1]
                return AnalyzerFrame('arg', frame.start_time, frame.end_time, {
                    'text': arg
                })

        if self.selected_output == 'MISO Frames':
            if 0 < frame_index <= len(rets):
                ret = rets[frame_index - 1]
                return AnalyzerFrame('ret', frame.start_time, frame.end_time, {
                    'text': ret
                })
            else:
                status = frame.data['miso'][0]
                command_status = (status >> 2) & 0b111

                if command_status in COMMAND_STATUS:
                    return AnalyzerFrame('status', frame.start_time, frame.end_time, {
                        'text': COMMAND_STATUS[command_status]
                    })



        # Return the data frame itself

