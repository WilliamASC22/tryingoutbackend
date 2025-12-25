Web Application Server

A full-stack web application that demonstrates real-time systems, authentication, media streaming, and secure deployment.


Running Locally

In terminal (after cloning the repository and cd'ing into it):
- chmod +x setup.sh
- ./setup.sh
- docker compose up

Visit https://localhost (HTTP automatically redirects to HTTPS)


Notes
- A browser security warning is expected due to the self-signed HTTPS certificate used for local development.
- No web frameworks (Flask, Django, FastAPI) were used


Highlights

- Custom Python HTTP server with manual Request/Response parsing, routing, and static file hosting

- Secure authentication with bcrypt password hashing, HttpOnly + Secure cookies, DOS attack prevention, TOTP-based 2FA, and RS256-signed JWTs

- Real-time features using WebSockets (chat, collaborative drawing board, active user lists, dirrect messaging, continuation and back-to-back frame handling)

- Media uploads and streaming with FFmpeg-generated thumbnails and HLS adaptive bit-rate delivery

- Zoom-style video calls using WebRTC with WebSocket-based signaling

- Fully containerized deployment using Docker Compose and an Nginx HTTPS reverse proxy

Tech Stack: Python, MongoDB, WebSockets, JWT, bcrypt, FFmpeg, HLS, Docker, Nginx, WebRTC

Architecture:
Client -> Nginx (HTTPS/WSS) -> App Server
-> Auth Server (JWT issuer)
-> MongoDB
