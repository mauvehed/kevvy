FROM python:3.13.6-slim

WORKDIR /app

# Copy only dependency files first
COPY pyproject.toml poetry.lock ./

# Install poetry and dependencies (excluding the project itself)
# Copying files first ensures README.md is present for project installation
RUN pip install --no-cache-dir poetry && \
    poetry config virtualenvs.create false && \
    poetry install --only main --no-root --no-interaction --no-ansi

# Copy the rest of the application code
COPY . .

# Now, install the application itself using the copied source
# Use pip to install the current project from source
RUN pip install .

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV DISCORD_TOKEN=""
ENV NVD_API_KEY=""
ENV VULNCHECK_API_TOKEN=""
ENV DISCORD_COMMAND_PREFIX="!"

# Run the application
CMD ["python", "main.py"]
