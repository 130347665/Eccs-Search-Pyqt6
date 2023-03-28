import asyncio
from aiohttp import ClientSession
import time


async def bai_du(url):
    print(f'启动时间: {time.time()}')
    async with ClientSession() as session:
        async with session.get(url) as response:
            res = await response.text()
            return res


async def main(url):
    url = "https://www.cnblogs.com/yoyoketang/"
    task_list = []
    for i in range(10):
        task = asyncio.create_task(bai_du(url))
        task_list.append(task)
    done, pending = await asyncio.wait(task_list, timeout=None)
    # 得到执行结果
    for done_task in done:
        print(f"{time.time()} 得到执行结果 {done_task.result()}")

# asyncio.run(main())
start_time = time.time()
loop = asyncio.get_event_loop()
loop.run_until_complete(main())
print("总耗时: ", time.time()-start_time)
