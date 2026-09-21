from pymodbus.server import StartTcpServer
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext, ModbusSequentialDataBlock

store = ModbusSlaveContext(
    hr=ModbusSequentialDataBlock(0, [0]*400)
)
context = ModbusServerContext(slaves={1: store, 10: store}, single=False)
print("PyModbus server running on port 10502...")
StartTcpServer(context=context, address=("0.0.0.0", 10502))