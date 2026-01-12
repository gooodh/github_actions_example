# FastAPI_SQLAlchemy_Temp

This project is a ready-made template for developing scalable web applications based on Facetapi with a full-fledged authentication and authorization system. The project includes a modular architecture, supports flexible logging with logoru, and database interaction via SQLAlchemy with asynchronous support.

## The main structure of the project

```
├── app/
│ ├── auth/
│ │ ├── auth.py
│ │ ├── dao.py
│ │ ├── dependencies.py
│ │ ├── models.py
│ │ ├── router.py
│ │ ├── schemas.py
│ │ └── utils.py
│ ├── dao/
│ │ └── base.py
│ ├── migration/
│ │ ├── versions/
│ │ ├── env.py
│ │ ├── README
│ │ └── script.py.mako
│ ├── static/
│ │ └── .gitkeep
│ ├── config.py
│ ├── database.py
│ ├── exceptions.py
│ ├── main.py
├── data/
│ └── db.sqlite3
├── .env
├── .gitignore
├── alembic.ini
├── README.md
├── command
├── docker-compose.yml
├── Dockerfile
├── entrypoint.sh
├── JSON_model.json
├── loki-config.yml
├── prometheus.yml
├── promtail-config.yaml
├── pyproject.toml
├── uv.lock
└── requirements.txt

```

## First, copy the application:
```bash
git clone git@github.com:gooodh/FastAPI_SQLAlchemy_Temp.git
```
## To launch, use the command:

```bash
docker compose up --build -d
```
## Grafana has been added to the app:

If Grafana is not needed, comment out these lines in docker-compose.yml
```yml
loki:
  image: grafana/loki:latest
  container_name: "grafana_loki"
  ports:
  - "3100:3100"
  volumes:
  - ./loki-config.yml:/etc/loki/local-config.yml:ro

grafana:
  image: grafana/grafana:latest
  container_name: "grafana"
  ports:
  - "3000:3000"
  volumes:
  - grafana_data:/var/lib/grafana

promtail:
  image: grafana/promtail:2.9.0
  container_name: promtail
  volumes:
  - /var/lib/docker/containers:/var/lib/docker/containers:ro
  - /var/run/docker.sock:/var/run/docker.sock
  - ./promtail-config.yaml:/etc/promtail/config.yml
  command: -config.file=/etc/promtail/config.yml
  privileged: true
  depends_on:
  - loki
prometheus:
  image: prom/prometheus:v2.52.0
  container_name: prometheus
  ports:
  - "9090:9090"
  volumes:
  - ./prometheus.yml:/etc/prometheus/prometheus.yml
  - ./prometheus-data:/prometheus
  command:
  - '--config.file=/etc/prometheus/prometheus.yml'
  - '--storage.tsdb.path=/prometheus'
  - '--web.enable-lifecycle'
  depends_on:
  - loki
```
## Чтобы получить такой дашборд:

Copy the contents of JSON_model.json to the Grafana settings

