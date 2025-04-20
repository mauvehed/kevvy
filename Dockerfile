FROM python:3.10.6-slim

WORKDIR /app

# Copy all project files first
COPY . .

# Install poetry and dependencies
# Copying files first ensures README.md is present for project installation
RUN pip install --no-cache-dir poetry && \
    poetry config virtualenvs.create false && \
    poetry install --no-interaction --no-ansi # Install project + dependencies

# No need for a second COPY . . as it's done above

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV DISCORD_TOKEN=""
ENV NVD_API_KEY=""
ENV DISCORD_COMMAND_PREFIX="!"

# Run the application
CMD ["python", "main.py"]