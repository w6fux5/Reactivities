using Application.Activities;
using Domain;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers
{
    public class ActivitiesController : BaseApiController
    {
        [HttpGet]
        public async Task<IActionResult> GetActivities(CancellationToken ct)
        {
            //ct 的作用是當使用者關閉瀏覽器等取消請求的動作時，會將做到一半的邏輯取消
            var result = await Mediator.Send(new List.Query(), ct);
            return HandleResult(result);
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetActivity(Guid id)
        {
            var result = await Mediator.Send(new Details.Query { Id = id });
            return HandleResult(result);
        }

        [HttpPost]
        public async Task<IActionResult> CreateActivity(Activity activity)
        {
            var result = await Mediator.Send(new Create.Command { Activity = activity });
            return HandleResult(result);
        }

        [HttpPut("{id}")]
        public async Task<IActionResult> EditActivity(Guid id, Activity activity)
        {
            activity.Id = id;
            var result = await Mediator.Send(new Edit.Command { Activity = activity });
            return HandleResult(result);
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteActivity(Guid id)
        {
            var result = await Mediator.Send(new Delete.Command { Id = id });
            return HandleResult(result);
        }
    }
}
