.PHONY: install scan test eval ui docker lab probe
install:        ## python deps (+ apt install tshark / brew install wireshark)
	pip install -r requirements.txt
scan:           ## scan the official samples -> out/
	python -m quantumtrace scan samples/official --out out
test:           ## unit + ground-truth tests
	QT_NOW=2026-10-10T12:00:00Z python -m pytest -q tests
eval:           ## accuracy report vs tests/ground_truth.json
	python -m quantumtrace.evaluate
ui:             ## dashboard on :8501
	python -m streamlit run app/streamlit_app.py
docker:         ## build + run the dashboard container
	docker build -t quantumtrace . && docker run --rm -p 8501:8501 quantumtrace
lab:            ## local TLS lab (needs Go >= 1.24): PQ, classical, legacy, STARTTLS, Postgres endpoints
	cd samples/extra/tls-lab && GODEBUG=tlsrsakex=1,tls3des=1,tls10server=1 go run .
probe:          ## live-probe the lab (run `make lab` in another terminal first)
	qtrace probe 127.0.0.1:8443 127.0.0.1:8444 127.0.0.1:8445 127.0.0.1:8446 127.0.0.1:8447 127.0.0.1:2525 127.0.0.1:5433
