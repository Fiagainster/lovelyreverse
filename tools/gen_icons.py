"""Generate cute icon candidates for lovelyreverse via Volcengine Ark (doubao-seedream).

Reads ARK_API_KEY from ./.env (never commit that file). Saves PNGs to assets/icons/.

Usage:
    python tools/gen_icons.py           # generate all candidates
    python tools/gen_icons.py A B       # regenerate selected candidates
"""

import os
import sys
import urllib.request
from pathlib import Path

import httpx
from openai import OpenAI

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "assets" / "icons"
MODEL = "doubao-seedream-5-0-260128"

CANDIDATES = {
    "A-heart-sprite": (
        "可爱风格应用图标，圆润的粉色爱心小精灵，大眼睛呆萌表情，头戴白色护目镜，"
        "一只手举着放大镜，放大镜镜片里显示十六进制字节块，另一只手握着小螺丝刀，"
        "爱心表面有细微的电路板纹理，玫瑰粉色主色调配奶油白背景，圆角方形徽章构图，"
        "扁平矢量插画风格，kawaii贴纸质感，居中构图，柔和光晕，干净简洁，无文字无字母"
    ),
    "B-girl-hacker": (
        "可爱风格应用图标，Q版二次元小女孩逆向工程师，头顶一根呆毛，穿oversize连帽卫衣，"
        "脖子上挂着头戴式耳机，怀里抱着笔记本电脑，电脑屏幕上是一颗粉色爱心和十六进制代码方块，"
        "周围漂浮着可爱的二进制符号，玫瑰粉配石墨灰配色，奶油白圆角方形徽章背景，"
        "扁平矢量插画风格，kawaii，居中构图，干净简洁，无文字无字母"
    ),
    "C-cat-techie": (
        "可爱风格应用图标，圆滚滚的粉色小猫技师，头顶戴着护目镜，爪子握着一把大扳手，"
        "身边漂浮着小齿轮和十六进制字节方块，肚皮上有一颗爱心图案，"
        "玫瑰粉主色调配薄荷绿点缀，奶油白圆角方形徽章构图，扁平矢量插画风格，"
        "kawaii贴纸质感，居中构图，柔和干净，无文字无字母"
    ),
}


def load_api_key() -> str:
    env_path = ROOT / ".env"
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("ARK_API_KEY="):
                return line.split("=", 1)[1].strip()
    key = os.environ.get("ARK_API_KEY")
    if not key:
        sys.exit("ARK_API_KEY not found in .env or environment")
    return key


def generate(client: OpenAI, prompt: str) -> bytes:
    try:
        resp = client.images.generate(
            model=MODEL,
            prompt=prompt,
            size="1024x1024",
            response_format="url",
            extra_body={"watermark": False},
        )
    except Exception as e:
        # fall back to preset size token if explicit dims are rejected
        print(f"  explicit 1024x1024 rejected ({e}); retrying with size='2K'")
        resp = client.images.generate(
            model=MODEL,
            prompt=prompt,
            size="2K",
            response_format="url",
            extra_body={"watermark": False},
        )
    url = resp.data[0].url
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()


def main() -> None:
    wanted = sys.argv[1:] or list(CANDIDATES)
    client = OpenAI(
        base_url="https://ark.cn-beijing.volces.com/api/v3",
        api_key=load_api_key(),
        # trust_env=False: 环境里的 NO_PROXY 含 "[::1]"，httpx 解析会炸；
        # Ark 是国内端点，直连即可，不走系统代理
        http_client=httpx.Client(trust_env=False, timeout=120),
    )
    OUT.mkdir(parents=True, exist_ok=True)
    for name in wanted:
        key = next((k for k in CANDIDATES if k.lower().startswith(name.lower())), None)
        if not key:
            print(f"unknown candidate '{name}', choices: {list(CANDIDATES)}")
            continue
        prompt = CANDIDATES[key]
        print(f"generating {key} …")
        data = generate(client, prompt)
        out = OUT / f"candidate-{key}.png"
        out.write_bytes(data)
        print(f"  saved {out} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
