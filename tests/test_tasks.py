"""Task CRUD tests, including access-control (IDOR) checks."""


def make_task(client, headers, title="Write report", **extra):
    r = client.post("/tasks", json={"title": title, **extra}, headers=headers)
    assert r.status_code == 201, r.text
    return r.json()


# ---------- Normal behaviour ----------

def test_create_and_read_task(client, alice):
    task = make_task(client, alice, description="Q4 summary")
    assert task["status"] == "todo"
    r = client.get(f"/tasks/{task['id']}", headers=alice)
    assert r.status_code == 200
    assert r.json()["description"] == "Q4 summary"


def test_list_only_returns_own_tasks(client, alice, bob):
    make_task(client, alice, "alice task")
    make_task(client, bob, "bob task")
    titles = [t["title"] for t in client.get("/tasks", headers=alice).json()]
    assert titles == ["alice task"]


def test_filter_by_status(client, alice):
    make_task(client, alice, "a")
    make_task(client, alice, "b", status="done")
    r = client.get("/tasks", params={"status_filter": "done"}, headers=alice)
    assert [t["title"] for t in r.json()] == ["b"]


def test_pagination_limit_is_capped(client, alice):
    for i in range(3):
        make_task(client, alice, f"t{i}")
    assert len(client.get("/tasks", params={"limit": 2}, headers=alice).json()) == 2
    assert len(client.get("/tasks", params={"limit": 100000}, headers=alice).json()) == 3


def test_update_task(client, alice):
    task = make_task(client, alice)
    r = client.patch(f"/tasks/{task['id']}", json={"status": "in_progress"}, headers=alice)
    assert r.status_code == 200
    assert r.json()["status"] == "in_progress"
    assert r.json()["title"] == "Write report"  # untouched fields are kept


def test_delete_task(client, alice):
    task = make_task(client, alice)
    assert client.delete(f"/tasks/{task['id']}", headers=alice).status_code == 204
    assert client.get(f"/tasks/{task['id']}", headers=alice).status_code == 404


def test_invalid_input_rejected(client, alice):
    assert client.post("/tasks", json={"title": ""}, headers=alice).status_code == 422
    assert client.post("/tasks", json={"title": "x", "status": "hacked"}, headers=alice).status_code == 422
    assert client.post("/tasks", json={"title": "x" * 201}, headers=alice).status_code == 422


# ---------- Access control (IDOR) ----------

def test_cannot_read_another_users_task(client, alice, bob):
    task = make_task(client, alice, "private")
    r = client.get(f"/tasks/{task['id']}", headers=bob)
    assert r.status_code == 404  # 404, not 403: don't reveal that the ID exists


def test_cannot_update_another_users_task(client, alice, bob):
    task = make_task(client, alice)
    r = client.patch(f"/tasks/{task['id']}", json={"title": "pwned"}, headers=bob)
    assert r.status_code == 404
    assert client.get(f"/tasks/{task['id']}", headers=alice).json()["title"] == "Write report"


def test_cannot_delete_another_users_task(client, alice, bob):
    task = make_task(client, alice)
    assert client.delete(f"/tasks/{task['id']}", headers=bob).status_code == 404
    assert client.get(f"/tasks/{task['id']}", headers=alice).status_code == 200


def test_existing_and_missing_ids_look_the_same_to_other_users(client, alice, bob):
    task = make_task(client, alice)
    exists = client.get(f"/tasks/{task['id']}", headers=bob)
    missing = client.get("/tasks/99999", headers=bob)
    assert exists.status_code == missing.status_code == 404
    assert exists.json() == missing.json()


def test_owner_id_in_body_is_ignored(client, alice, bob):
    """Mass-assignment check: Bob can't create a task in Alice's account."""
    alice_id = client.get("/auth/me", headers=alice).json()["id"]
    make_task(client, bob, "sneaky", owner_id=alice_id)
    assert client.get("/tasks", headers=alice).json() == []
    assert len(client.get("/tasks", headers=bob).json()) == 1
