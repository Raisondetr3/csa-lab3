#!/usr/bin/python3
import logging
import sys

from isa import *

class ALU:
    def __init__(self):
        self.left = 0
        self.right = 0
        self.N = 0
        self.Z = 1
        self.C = 0

    def set_flags(self, res):
        self.N = 1 if res < 0 else 0
        self.Z = 1 if res == 0 else 0

    def invert_string(self, s):
        return "".join(["1" if c == "0" else "0" for c in s])

    def to_unsigned(self, a):
        return int(self.invert_string(bin(abs(a))[2:].zfill(REAL_RANGE)), 2) + 1

    def to_signed(self, a):
        self.C = 1 if a >= REAL_MAX else 0
        a = a if self.C == 0 else a % REAL_MAX
        return a if MAX_NUM > a >= -MAX_NUM else -self.to_unsigned(a)

    def add(self, a, b):
        a = a if a >= 0 else self.to_unsigned(a)
        b = b if b >= 0 else self.to_unsigned(b)
        return self.to_signed(a + b)

    def sub(self, a, b):
        a = a if a >= 0 else self.to_unsigned(a)
        b = b if b >= 0 else self.to_unsigned(b)
        return self.add(a, self.to_unsigned(b))

    def div(self, a):
        self.C = a % 2
        return a // 2

    def calc_op(self, left, right, op_type):
        if op_type == "add":
            return self.add(left, right)
        elif op_type == "sub" or op_type == "cmp":
            return self.sub(left, right)
        raise Exception("Incorrect binary operation")

    def calc_nop(self, res, op_type):
        if op_type == "asl":
            return self.add(res, res)
        elif op_type == "asr":
            return self.div(res)
        elif op_type == "inc":
            return self.add(res, 1)
        elif op_type == "dec":
            return self.sub(res, 1)
        raise Exception("Incorrect unary operation")

    def calc(self, left, right, op_type, change_flags=False):
        is_left_char = True if isinstance(left, str) else False
        left = ord(left) if is_left_char else int(left)
        C = self.C

        if right is None:
            res = left
            is_right_char = False
            res = self.calc_nop(res, op_type)
        else:
            is_right_char = True if isinstance(right, str) else False
            right = ord(right) if is_right_char else int(right)
            res = self.calc_op(left, right, op_type)
        if change_flags:
            self.set_flags(res)
        else:
            self.C = C
        if is_left_char or is_right_char:
            res = chr(res)
            if is_left_char:
                left = chr(left)
        return left if op_type == "cmp" else res

class DataPath:
    registers = {"AC": 0, "AR": 0, "IP": 0, "PC": 0, "PS": 0, "DR": 0, "CR": 0}
    memory = []
    alu = ALU()

    def __init__(self, input_buffer):
        self.mem_size = MAX_ADDR + 1
        self.memory = [{"value": 0}] * self.mem_size
        self.registers["AC"] = 0
        self.registers["PS"] = 2  # self.Z = 1
        self.output_buffer = []
        self.input_buffer = input_buffer
        self.ignoreBuffer = False

    def get_reg(self, reg):
        return self.registers[reg]

    def set_reg(self, reg, val):
        self.registers[reg] = val

    def wr(self):
        self.memory[self.registers["AR"]] = {"value": self.registers["DR"]}
        if self.registers["AR"] == OUTPUT_MAP:
            if isinstance(self.registers["DR"], int) and 0 <= self.registers["DR"] <= 0x10FFFF:
                self.output_buffer.append(chr(self.registers["DR"]))
                logging.debug("OUTPUT " + str(self.output_buffer[-1]))
            else:
                self.output_buffer.append(self.registers["DR"])
                logging.debug("OUTPUT " + str(self.output_buffer[-1]))



    def rd(self):
        self.registers["DR"] = self.memory[self.registers["AR"]]["value"]
        if self.registers["AR"] == INPUT_MAP:
            if self.input_buffer:
                self.registers["DR"] = ord(self.input_buffer.pop(0))
                logging.debug("INPUT " + chr(self.registers["DR"]))

class ControlUnit:
    def __init__(self, program, data_path, start_address, limit):
        self.program = program
        self.data_path = data_path
        self.limit = limit
        self.instr_counter = 0
        self._tick = 0

        self.sig_latch_reg("IP", start_address)
        self._map_instruction()

    def _map_instruction(self):
        for i in self.program:
            self.data_path.memory[int(i["index"])] = i

    def get_reg(self, reg):
        return self.data_path.get_reg(reg)

    def sig_latch_reg(self, reg, val):
        self.data_path.set_reg(reg, val)

    def sig_write(self):
        self.data_path.wr()

    def sig_read(self):
        self.data_path.rd()

    def tick(self):
        self._tick += 1

    def current_tick(self):
        return self._tick

    def calc(self, left, right, op, change_flags=False):
        res = self.data_path.alu.calc(left, right, op, change_flags)
        if change_flags:
            self.sig_latch_reg("PS", self.get_reg("PS") ^ ((self.get_reg("PS") ^ self.data_path.alu.C) & 1))
            self.sig_latch_reg(
                "PS", self.get_reg("PS") ^ ((self.get_reg("PS") ^ (self.data_path.alu.Z << 1)) & (1 << 1))
            )
            self.sig_latch_reg(
                "PS", self.get_reg("PS") ^ ((self.get_reg("PS") ^ (self.data_path.alu.N << 2)) & (1 << 2))
            )
        return res

    def command_cycle(self):
        while self.instr_counter < self.limit:
            go_next = self.decode_and_execute_instruction()
            if not go_next:
                return
            self.instr_counter += 1
            self.__print__()
        if self.instr_counter >= self.limit:
            logging.warning("Limit exceeded!")

    def decode_and_execute_instruction(self):
        self.sig_latch_reg("AR", self.calc(0, self.get_reg("IP"), "add"))  # IP -> AR
        self.sig_latch_reg("IP", self.calc(1, self.get_reg("IP"), "add"))  # IP + 1 -> AR
        self.sig_latch_reg("CR", self.data_path.memory[self.get_reg("AR")])
        instr = self.get_reg("CR")

        opcode = instr["opcode"]

        self.tick()

        if "opcode" not in instr.keys():
            return False

        # адресная команда
        if "operand" in instr.keys():
            # в DR лежит адрес операнда или адрес адреса операнда
            self.sig_latch_reg("DR", int(self.get_reg("CR")["operand"]))  # CR -> alu -> DR (operand only)

            # цикл выборки адреса
            if instr["address"]:
                self.sig_latch_reg("AR", self.calc(0, self.get_reg("DR"), "add"))
                self.sig_read()
                self.tick()

            # цикл выборки операнда
            self.sig_latch_reg("AR", self.calc(0, self.get_reg("DR"), "add"))
            self.sig_read()
            self.tick()

            if opcode == "load":
                self.sig_latch_reg("AC", self.calc(0, self.get_reg("DR"), "add", True))
                self.tick()

            elif opcode == "store":
                self.sig_latch_reg("DR", self.calc(0, self.get_reg("AC"), "add"))
                self.sig_write()
                self.tick()

            elif opcode in branch_commands:
                ind = branch_commands.index(opcode)
                flag = branch_flags[ind]
                condition = True

                if (flag is not None) and flag[0] == "!":
                    condition = eval("not self.data_path.alu." + flag[1])
                elif flag is not None:
                    condition = eval("self.data_path.alu." + flag[0])
                if condition:
                    self.sig_latch_reg("IP", self.calc(0, self.get_reg("AR"), "add"))
                self.tick()
            else:
                # арифметическая операция
                self.sig_latch_reg("AC", self.calc(self.get_reg("AC"), self.get_reg("DR"), opcode, True))
                self.tick()
        # безадресная команда
        else:
            if opcode == "hlt":
                self.tick()
                self.__print__()
                return False

            elif opcode == "cla":
                self.sig_latch_reg("AC", self.calc(self.get_reg("AC"), self.get_reg("AC"), "sub", True))
                self.tick()
            elif opcode == "nop":
                self.tick()
            else:
                # унарная арифметическая операция
                self.sig_latch_reg("AC", self.calc(self.get_reg("AC"), None, opcode, True))
                self.tick()
        return True

    def __print_symb__(self, text):
        return str((lambda x: ord(x) if isinstance(x, str) else x)(text))

    def __print__(self):
        state_repr = (
            "TICK: {:4} | AC {:7} | IP: {:4} | AR: {:4} | PS: {:3} | DR: {:7} | mem[AR] {:7} | CR: {:12} |"
        ).format(
            self.current_tick(),
            self.__print_symb__(self.get_reg("AC")),
            str(self.get_reg("IP")),
            str(self.get_reg("AR")),
            str(bin(self.get_reg("PS"))[2:].zfill(3)),
            self.__print_symb__(self.get_reg("DR")),
            self.__print_symb__(self.data_path.memory[self.get_reg("AR")]["value"]),
            self.get_reg("CR")["opcode"]
            + (lambda x: " " + str(x["operand"]) if "operand" in x.keys() else "")(self.get_reg("CR")),
        )
        logging.debug(state_repr)


def simulation(code, limit, input_data, start_addr):
    start_address = start_addr
    data_path = DataPath(input_data)
    control_unit = ControlUnit(code, data_path, start_address, limit)
    control_unit.command_cycle()
    return [control_unit.data_path.output_buffer, control_unit.instr_counter, control_unit.current_tick()]

def main(code, input_f):
    with open(input_f, encoding="utf-8") as file:
        input_text = file.read()
        input_token = list(input_text)

    start_addr, code = read_code(code)
    output, instr_num, ticks = simulation(
        code,
        limit=1500,
        input_data=input_token,
        start_addr=start_addr,
    )

    output_str = ''.join(map(str, output))
    print(f"Output: {output_str}\nInstruction number: {instr_num}\nTicks: {ticks}")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(levelname)-7s %(module)s:%(funcName)-13s %(message)s',
        handlers=[logging.StreamHandler(sys.stdout)]
    )
    assert len(sys.argv) == 3, "Wrong arguments: machine.py <code_file> <input_file>"
    _, code_file, input_file = sys.argv
    main(code_file, input_file)