FROM python:3.13.3-slim

WORKDIR /app

# Copy only dependency files first
COPY pyproject.toml poetry.lock ./

# Install poetry and dependencies (excluding the project itself)
# Copying files first ensures README.md is present for project installation
RUN pip install --no-cache-dir poetry && \
    poetry config virtualenvs.create false && \
    # poetry install --no-interaction --no-ansi # Install project + dependencies
    poetry install --no-root --no-interaction --no-ansi # Reverted to --no-root, removed -vvv

# Copy the rest of the application code
COPY . .

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV DISCORD_TOKEN=""
ENV NVD_API_KEY=""
ENV VULNCHECK_API_TOKEN=""
ENV DISCORD_COMMAND_PREFIX="!"

# Run the application
CMD ["python", "main.py"]