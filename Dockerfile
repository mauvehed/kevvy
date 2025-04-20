FROM python:3.10.6-slim

WORKDIR /app

# Copy only dependency files first
COPY pyproject.toml poetry.lock ./

# Install poetry and dependencies
RUN pip install --no-cache-dir poetry && \
    poetry config virtualenvs.create false && \
    poetry install --no-interaction --no-ansi

# Copy the rest of the application code
COPY . .

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV DISCORD_TOKEN=""
ENV NVD_API_KEY=""
ENV DISCORD_COMMAND_PREFIX="!"

# Run the application
CMD ["python", "main.py"]