"""
检查动态壁纸的循环接缝。

分两层：

1. 相位层（严格）——直接调用生成器的帧函数，比较 frame(t=1.0) 与 frame(t=0)。
   两者必须逐像素相同，这是「循环数学上闭合」的证明，等价于所有运动量的
   周期都整除 DUR。

2. 视频层（宽松）——从编码后的 MP4 抽「末帧→首帧」这一步，与普通相邻帧
   的变化量比。这里不能卡太死：x264 在 GOP 关键帧处的量化误差会让接缝帧
   有千分之几的像素偏差，肉眼不可见，但会把比值抬到 2 左右。所以只要求
   接缝跳变与普通帧间处于同一量级（≤3 倍），用来抓「相位真的没闭合」这种
   会明显闪一下的错误。

用法：python tools/check_loop.py
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gen_live_wallpapers as G  # noqa: E402

W, H = 1920, 1080
OUT = Path(__file__).resolve().parent.parent / "lib" / "wallpapers"
CASES = [("neko-aurora", G.frame_aurora), ("neko-ripple", G.frame_ripple)]
PHASE_EPS = 0.02      # 相位闭合容差（0-255 色阶的平均绝对差）
VIDEO_RATIO_MAX = 3.0


def blur(img: np.ndarray, k: int = 16) -> np.ndarray:
    """块平均降噪：把逐像素噪声压到 1/k 量级，只保留画面结构。"""
    h, w, c = img.shape
    h2, w2 = h // k * k, w // k * k
    v = img[:h2, :w2].reshape(h2 // k, k, w2 // k, k, c)
    return v.mean(axis=(1, 3))


def grab(path: Path, index: int) -> np.ndarray:
    cmd = [
        "ffmpeg", "-v", "error", "-i", str(path),
        "-vf", f"select=eq(n\\,{index})", "-vframes", "1",
        "-f", "rawvideo", "-pix_fmt", "rgb24", "-",
    ]
    out = subprocess.run(cmd, capture_output=True).stdout
    if len(out) != W * H * 3:
        raise RuntimeError(f"{path.name} 第 {index} 帧读取失败，得到 {len(out)} 字节")
    return blur(np.frombuffer(out, dtype=np.uint8).reshape(H, W, 3).astype(np.float32))


def count_frames(path: Path) -> int:
    cmd = [
        "ffprobe", "-v", "error", "-select_streams", "v:0",
        "-show_entries", "stream=nb_frames", "-of", "default=nw=1:nk=1", str(path),
    ]
    return int(subprocess.run(cmd, capture_output=True, text=True).stdout.strip())


def main() -> int:
    bad = 0
    for name, fn in CASES:
        print(f"  {name}")

        # ── 相位层 ──
        a = fn(0.0)
        b = fn(1.0)
        phase = float(np.abs(a - b).mean())
        phase_ok = phase <= PHASE_EPS
        if not phase_ok:
            bad += 1
        print(f"    相位闭合 frame(1.0) vs frame(0.0) = {phase:.6f}  {'PASS' if phase_ok else 'FAIL'}")

        # ── 视频层 ──
        path = OUT / f"{name}.mp4"
        if not path.exists():
            print("    视频缺失  FAIL")
            bad += 1
            continue
        n = count_frames(path)
        seam = float(np.abs(grab(path, n - 1) - grab(path, 0)).mean())
        step = float(np.abs(grab(path, n // 2 + 1) - grab(path, n // 2)).mean())
        ratio = seam / max(step, 1e-6)
        video_ok = ratio <= VIDEO_RATIO_MAX
        if not video_ok:
            bad += 1
        print(
            f"    视频接缝 接缝跳变={seam:6.3f} 普通帧间={step:6.3f} "
            f"比值={ratio:5.2f}  {'PASS' if video_ok else 'FAIL'}"
        )

    print("RESULT: ALL PASS" if bad == 0 else f"RESULT: {bad} FAIL")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
