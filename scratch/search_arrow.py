import pyarrow as pa
import pyarrow.ipc as ipc

path = "/home/mertk/Codebase/Python/codevuln/data/walledai___cyber_sec_eval/instruct/0.0.0/62dba0bb39c450c375aff453d3396fa8f2338eee/cyber_sec_eval-python.arrow"

with pa.memory_map(path, 'rb') as source:
    table = ipc.RecordBatchStreamReader(source).read_all()

df = table.to_pandas()
row = df.iloc[36]
for key, val in row.items():
    print(f"=== {key} ===")
    print(val)
    print()
