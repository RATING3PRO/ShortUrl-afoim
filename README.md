# ShortUrl

Simple URL Shortener with Admin Interface.

## Deployment

### Docker (Recommended)

You can run this project easily using Docker Compose.

1.  **Build and Run**

    ```bash
    docker-compose up -d --build
    ```

    The application will be available at `http://localhost:3000`.

2.  **Configuration**

    You can configure the following environment variables in `docker-compose.yml`:

    *   `JWT_SECRET`: Secret key for authentication (Change this for production!)
    *   `PORT`: Port to listen on (Default: 3000)

3.  **Data Persistence**

    The SQLite database is stored in the `./data` directory on your host machine, mapped to `/app/data` in the container.

### GitHub Actions

This repository includes a GitHub Workflow `.github/workflows/docker-build.yml` that automatically:

*   Builds the Docker image on push to `main` or when a tag starting with `v` is pushed.
*   Pushes the image to GitHub Container Registry (GHCR).

**Note:** To use GHCR, ensure your repository Settings > Actions > General > Workflow permissions are set to "Read and write permissions".
