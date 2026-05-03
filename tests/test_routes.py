class TestMainBlueprint:
    def test_home_page(self, client):
        assert client.get("/").status_code == 200

    def test_privacy_page(self, client):
        assert client.get("/privacy").status_code == 200

    def test_robots_txt(self, client):
        assert client.get("/robots.txt").status_code == 200

    def test_sitemap(self, client):
        assert client.get("/sitemap.xml").status_code == 200

    def test_favicon(self, client):
        assert client.get("/favicon.ico").status_code == 200


class TestAuthBlueprint:
    def test_login_page(self, client):
        assert client.get("/login").status_code == 200

    def test_admin_requires_login(self, client):
        response = client.get("/admin")
        assert response.status_code in (302, 401)


class TestHealthCheck:
    def test_health(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.get_json() == {"status": "ok"}


class TestErrorHandling:
    def test_404(self, client):
        assert client.get("/route/does/not/exist").status_code == 404
