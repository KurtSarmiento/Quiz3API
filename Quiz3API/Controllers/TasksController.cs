using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Quiz3API.Controllers
{
    [Route("api/tasks")]
    [ApiController]
    [EnableRateLimiting("TasksPolicy")]
    public class TasksController : ControllerBase
    {
        private static List<TaskItem> _tasks = new List<TaskItem>();

        private static int _currentId = 1;
        public class TaskItem
        {
            public int Id { get; set; }
            public string Title { get; set; }
            public bool IsCompleted { get; set; }
        }

        [Authorize(Roles = "Admin,User")]
        [HttpGet]
        public IActionResult GetAll()
        {
            return Ok(_tasks);
        }

        [Authorize(Roles = "Admin,User")]
        [HttpGet("{id}")]
        public IActionResult GetById(int id)
        {
            var task = _tasks.FirstOrDefault(t => t.Id == id);
            if (task == null)
                return NotFound();
            return Ok(task);
        }

        [Authorize(Roles = "Admin,User")]
        [HttpPost]
        public IActionResult Create(TaskItem task)
        {
            task.Id = _currentId++;
            _tasks.Add(task);
            return Ok($"Task '{task.Title}' with ID: {task.Id} has been created");
        }

        [Authorize(Roles = "Admin")]
        [HttpPut("{id}")]
        public IActionResult Update(int id, TaskItem updatedTask)
        {
            var task = _tasks.FirstOrDefault(t => t.Id == id);
            if (task == null)
                return NotFound();
            task.Title = updatedTask.Title;
            task.IsCompleted = updatedTask.IsCompleted;
            return Ok($"Task '{task.Title}' with ID: {task.Id} has been updated");
        }

        [Authorize(Roles = "Admin")]
        [HttpDelete("{id}")]
        public IActionResult Delete(int id)
        {
            var task = _tasks.FirstOrDefault(t => t.Id == id);
            if (task == null)
                return NotFound();
            _tasks.Remove(task);
            return Ok($"Task '{task.Title}' with ID: {task.Id} has been deleted");
        }
    }
}