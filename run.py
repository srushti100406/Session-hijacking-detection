"""
run.py — Entry point for the Session Hijacking Detection & Prevention System.
"""
from app import create_app
from config import Config

app = create_app(Config)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Session Hijacking Detection Demo Server")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on")
    parser.add_argument("--debug", action="store_true", default=False)
    args = parser.parse_args()

    app.config["SIMULATOR_PORT"] = args.port
    print(f"\n{'='*60}")
    print("  Session Hijacking Detection & Prevention System")
    print(f"  Running at: http://127.0.0.1:{args.port}")
    print(f"  Demo user:  alice / Demo@1234")
    print(f"{'='*60}\n")

    app.run(host="127.0.0.1", port=args.port, debug=args.debug, threaded=True)
