"""
main.py — entry point for win-computer-use.

Usage:
    python main.py
    python main.py --prompt "Open Notepad and type hello world"
"""

import argparse
import os

from dotenv import load_dotenv

from win_computer_use.agent import WindowsAgent
from win_computer_use.logging import Logger
from win_computer_use.windows_desktop import WindowsDesktop

load_dotenv()

logger = Logger()


def initialize_output_directory(fmt):
    run_id = 1
    while os.path.exists(fmt(run_id)):
        run_id += 1
    os.makedirs(fmt(run_id), exist_ok=True)
    return fmt(run_id)


def main():
    parser = argparse.ArgumentParser(description="Windows computer-use agent")
    parser.add_argument("--prompt", type=str, help="Initial task for the agent")
    parser.add_argument(
        "--monitor", type=int, default=1,
        help="Monitor index to capture (1 = primary, 2 = secondary, 0 = all). Default: 1"
    )
    args = parser.parse_args()

    output_dir = initialize_output_directory(lambda i: f"./output/run_{i}")
    desktop = WindowsDesktop(monitor_index=args.monitor)
    agent = WindowsAgent(desktop, output_dir=output_dir)

    user_input = args.prompt
    while True:
        if user_input is None:
            try:
                user_input = input("USER: ").strip()
                if not user_input:
                    continue
            except KeyboardInterrupt:
                print("\nExiting.")
                break
        try:
            agent.run(user_input)
            user_input = None
        except KeyboardInterrupt:
            print("\n(Interrupted. Enter next task or Ctrl-C again to exit.)")
            user_input = None
        except Exception as e:
            logger.print_colored(f"Error: {e}", "red")
            user_input = None


if __name__ == "__main__":
    main()
