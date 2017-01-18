{if !empty($message)}<p>{$message}</p><br />{/if}
{$startform}
{if ($ucount > 0)}
<div style="overflow:auto;">
 <table id="userstable" class="leftwards pagetable">
  <thead><tr>
   <th>{$title_name}</th>
   <th>{$title_first}</th>
   <th>{$title_last}</th>
   <th>{$title_addr}</th>
   <th>{$title_active}</th>
   <th class="pageicon"></th>
{if $mod} <th class="pageicon"></th>
   <th class="pageicon"></th>
   <th class="checkbox"></th>{/if}
  </tr></thead>
  <tbody>
 {foreach from=$users item=entry} {cycle values='row1,row2' assign='rowclass'}
  <tr class="{$rowclass}" onmouseover="this.className='{$rowclass}hover';" onmouseout="this.className='{$rowclass}';">
   <td>{$entry->name}</td>
   <td>{$entry->reg}</td>
   <td>{$entry->last}</td>
   <td>{$entry->addr}</td>
   <td>{$entry->active}</td>
   <td>{$entry->see}</td>
{if $mod} <td>{$entry->edit}</td>
   <td class="linkdel">{$entry->del}</td>
   <td class="checkbox">{$entry->sel}</td>{/if}
  </tr>
 {/foreach}
  </tbody>
 </table>
</div>
{else}
 <p class="pageinput">{$nousers}</p>
{/if}
<div id="itemacts" class="pageoptions" style="margin-top:1em;">
{if $mod}{$iconlinkadd} {$textlinkadd}<span style="margin-left:12em;">{/if}
{$close}
{if $mod}{if ($ucount > 0)} {$delete} {/if}{$import}</span>{/if}
</div>
{$endform}
