#!/usr/bin/python3
import logging
import sys

from isa import *

logger = logging.getLogger("machine_logger")
logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter("%(message)s")
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

N, Z, C = 0, 0, 0

def set_flags(res):
    N = 1 if res < 0 else 0
    Z = 1 if res == 0 else 0
    return N, Z

def invert_string(s):
    return "".join(["1" if c == "0" else "0" for c in s])

def to_unsigned(a):
    return int(invert_string(bin(abs(a))[2:].zfill(REAL_RANGE)), 2) + 1

def to_signed(a):
    C = 1 if a >= REAL_MAX else 0
    a = a if C == 0 else a % REAL_MAX
    return (a if MAX_NUM > a >= -MAX_NUM else -to_unsigned(a)), C

def add(a, b):
    a = a if a >= 0 else to_unsigned(a)
    b = b if b >= 0 else to_unsigned(b)
    return to_signed(a + b)

def sub(a, b):
    a = a if a >= 0 else to_unsigned(a)
    b = b if b >= 0 else to_unsigned(b)
    return add(a, to_unsigned(b))

def div(a):
    C = a % 2
    return a // 2, C

def calc_op(left, right, op_type):
    if op_type == "add":
        return add(left, right)
    elif op_type == "sub" or op_type == "cmp":
        return sub(left, right)
    raise Exception("Incorrect binary operation")

def calc_nop(res, op_type):
    if op_type == "asl":
        return add(res, res)
    elif op_type == "asr":
        return div(res)
    elif op_type == "inc":
        return add(res, 1)
    elif op_type == "dec":
        return sub(res, 1)
    raise Exception("Incorrect unary operation")

def alu_calc(left, right, op_type, change_flags=False):
    is_left_char = True if isinstance(left, str) else False
    left = ord(left) if is_left_char else int(left)

    if right is None:
        res = left
        is_right_char = False
        res, C = calc_nop(res, op_type)
    else:
        is_right_char = True if isinstance(right, str) else False
        right = ord(right) if is_right_char else int(right)
        res, C = calc_op(left, right, op_type)
    N, Z = set_flags(res) if change_flags else (0, 0)
    if is_left_char or is_right_char:
        res = chr(res)
        if is_left_char:
            left = chr(left)
    return left if op_type == "cmp" else res, N, Z, C


class DataPath:
    registers = {"AC": 0, "AR": 0, "IP": 0, "PC": 0, "PS": 0, "DR": 0, "CR": 0}
    memory = []

    def __init__(self):
        self.mem_size = MAX_ADDR + 1
        self.memory = [{"value": 0}] * self.mem_size
        self.registers["AC"] = 0
        self.registers["PS"] = 2  # self.Z = 1
        self.output_buffer = []
        self.input_buffer = []

    def get_reg(self, reg):
        return self.registers[reg]

    def set_reg(self, reg, val):
        self.registers[reg] = val

    def wr(self):
        self.memory[self.registers["AR"]] = {"value": self.registers["DR"]}
        if self.registers["AR"] == OUTPUT_MAP:
            self.output_buffer.append(self.registers["DR"])
            logger.info("OUTPUT " + str(self.output_buffer[-1]))

    def rd(self):
        self.registers["DR"] = self.memory[self.registers["AR"]]["value"]
        if self.registers["AR"] == INPUT_MAP:
            if self.input_buffer:
                self.registers["DR"] = self.input_buffer.pop(0)
                logger.info("INPUT " + str(self.registers["DR"]))


class ControlUnit:
    def __init__(self, program, data_path, start_address, input_data, limit, tick):
        self.program = program
        self.data_path = data_path
        self.limit = limit
        self.instr_counter = 0
        self._tick = 0

        self.sig_latch_reg("IP", start_address)
        self._map_instruction()

        self.input_data = input_data
        self.input_pointer = 0

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
        res, N, Z, C = alu_calc(left, right, op, change_flags)
        if change_flags:
            self.sig_latch_reg("PS", self.get_reg("PS") ^ ((self.get_reg("PS") ^ C) & 1))
            self.sig_latch_reg(
                "PS", self.get_reg("PS") ^ ((self.get_reg("PS") ^ (Z << 1)) & (1 << 1))
            )
            self.sig_latch_reg(
                "PS", self.get_reg("PS") ^ ((self.get_reg("PS") ^ (N << 2)) & (1 << 2))
            )
        return res

    def command_cycle(self, mode="main: "):
        while self.instr_counter < self.limit:
            go_next = self.decode_and_execute_instruction(mode)
            if not go_next:
                return
            self.instr_counter += 1
            self.__print__("")
        if self.instr_counter >= self.limit:
            pass
            print("Limit exceeded!")

    def decode_and_execute_instruction(self, mode=""):
        self.sig_latch_reg("AR", self.calc(0, self.get_reg("IP"), "add"))  # IP -> AR
        self.sig_latch_reg("IP", self.calc(1, self.get_reg("IP"), "add"))  # IP + 1 -> AR
        self.sig_latch_reg("CR", self.data_path.memory[self.get_reg("AR")])
        instr = self.get_reg("CR")
        opcode = instr["opcode"]

        if "opcode" not in instr.keys():
            return False

        cycle = "exec.f: "
        # адресная команда
        if "operand" in instr.keys():
            # в DR лежит адрес операнда или адрес адреса операнда
            self.sig_latch_reg("DR", int(self.get_reg("CR")["operand"]))  # CR -> alu -> DR (operand only)

            # цикл выборки адреса
            if instr["address"]:
                self.sig_latch_reg("AR", self.calc(0, self.get_reg("DR"), "add"))
                self.sig_read()

            # цикл выборки операнда
            self.sig_latch_reg("AR", self.calc(0, self.get_reg("DR"), "add"))
            self.sig_read()

            if opcode == "load":
                self.sig_latch_reg("AC", self.calc(0, self.get_reg("DR"), "add", True))

            elif opcode == "store":
                self.sig_latch_reg("DR", self.calc(0, self.get_reg("AC"), "add"))
                self.sig_write()

            elif opcode in branch_commands:
                ind = branch_commands.index(opcode)
                flag = branch_flags[ind]
                condition = True

                if (flag is not None) and flag[0] == "!":
                    condition = eval("not self.get_flag('" + flag[1] + "')")
                elif flag is not None:
                    condition = eval("self.get_flag('" + flag[0] + "')")
                if condition:
                    self.sig_latch_reg("IP", self.calc(0, self.get_reg("AR"), "add"))
                else:
                    pass
            else:
                # арифметическая операция
                self.sig_latch_reg("AC", self.calc(self.get_reg("AC"), self.get_reg("DR"), opcode, True))
        # безадресная команда
        else:
            if opcode == "hlt":
                return False

            elif opcode == "cla":
                self.sig_latch_reg("AC", self.calc(self.get_reg("AC"), self.get_reg("AC"), "sub", True))
            elif opcode == "nop":
                pass
            else:
                # унарная арифметическая операция
                self.sig_latch_reg("AC", self.calc(self.get_reg("AC"), None, opcode, True))
        return True  # executed successfully

    def get_flag(self, flag):
        PS = self.get_reg("PS")
        if flag == 'N':
            return (PS >> 2) & 1
        elif flag == 'Z':
            return (PS >> 1) & 1
        elif flag == 'C':
            return PS & 1
        return 0

    def __print_symb__(self, text):
        return str((lambda x: ord(x) if isinstance(x, str) else x)(text))

    def __print__(self, comment):
        state_repr = (
            "TICK: {:4} | AC {:7} | IP: {:4} | AR: {:4} | PS: {:3} | DR: {:7} | mem[AR] {:7} | CR: {:12} |"
        ).format(
            self.instr_counter,
            self.__print_symb__(self.get_reg("AC")),
            str(self.get_reg("IP")),
            str(self.get_reg("AR")),
            str(bin(self.get_reg("PS"))[2:].zfill(5)),
            self.__print_symb__(self.get_reg("DR")),
            self.__print_symb__(self.data_path.memory[self.get_reg("AR")]["value"]),
            self.get_reg("CR")["opcode"]
            + (lambda x: " " + str(x["operand"]) if "operand" in x.keys() else "")(self.get_reg("CR")),
        )
        return state_repr + " " + comment


def simulation(code, limit, input_data, start_addr):
    start_address = start_addr
    data_path = DataPath()
    _tick = None
    control_unit = ControlUnit(code, data_path, start_address, input_data, limit, _tick)
    control_unit.command_cycle()
    return [control_unit.data_path.output_buffer, control_unit.instr_counter]


def main(code, input_f):
    with open(input_f, encoding="utf-8") as file:
        input_text = file.read()
        if not input_text:
            input_token = []
        else:
            input_token = eval(input_text)  # массив символов для ввода
    start_addr, code = read_code(code)
    output, instr_num = simulation(
        code,
        limit=1500,
        input_data=input_token,
        start_addr=start_addr,
    )
    print(f"Output: {output}\nInstruction number: {instr_num}")


if __name__ == "__main__":
    assert len(sys.argv) == 3, "Wrong arguments: machine.py <code_file> <input_file>"
    _, code_file, input_file = sys.argv
    d = DataPath()
    main(code_file, input_file)
