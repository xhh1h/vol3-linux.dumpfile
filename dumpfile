import logging
from typing import List, Optional, Type

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.linux import pslist

vollog = logging.getLogger(__name__)

class DumpFiles(plugins.PluginInterface):
    """Dump memory-mapped files from Linux processes."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
            requirements.StringRequirement(
                name="name",
                description="Filter mapped files by name (substring match)",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Dump the mapped file content",
                default=False,
                optional=True,
            ),
        ]

    @classmethod
    def dump_vma(
        cls,
        context: interfaces.context.ContextInterface,
        proc_layer_name: str,
        vma: interfaces.objects.ObjectInterface,
        task: interfaces.objects.ObjectInterface,
        open_method: Type[interfaces.plugins.FileHandlerInterface],
    ) -> Optional[interfaces.plugins.FileHandlerInterface]:
        """Dump a memory region (VMA) to a file."""

        proc_layer = context.layers[proc_layer_name]
        size = vma.vm_end - vma.vm_start

        try:
            buf = proc_layer.read(vma.vm_start, size, pad=True)
        except Exception as e:
            vollog.debug(f"Failed to read VMA: {e}")
            return None

        filename = f"pid.{task.pid}.{utility.array_to_string(task.comm)}.{vma.vm_start:#x}.dmp"
        file_handle = open_method(filename)
        file_handle.write(buf)
        return file_handle

    def _generator(self, tasks):
        for task in tasks:
            proc_layer_name = task.add_process_layer()
            if not proc_layer_name:
                continue

            name = utility.array_to_string(task.comm)

            for vma in task.mm.get_vma_iter():
                path = vma.get_name(self.context, task) or ""

                # name filter
                if self.config.get("name") and self.config["name"] not in path:
                    continue

                file_output = "Disabled"
                if self.config["dump"]:
                    file_handle = self.dump_vma(
                        self.context, proc_layer_name, vma, task, self.open
                    )
                    file_output = "Error"
                    if file_handle:
                        file_handle.close()
                        file_output = str(file_handle.preferred_filename)

                yield (
                    0,
                    (
                        task.pid,
                        name,
                        format_hints.Hex(vma.vm_start),
                        format_hints.Hex(vma.vm_end),
                        path or renderers.NotAvailableValue(),
                        file_output,
                    ),
                )

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Start", format_hints.Hex),
                ("End", format_hints.Hex),
                ("File Path", str),
                ("File Output", str),
            ],
            self._generator(
                pslist.PsList.list_tasks(
                    self.context, self.config["kernel"], filter_func=filter_func
                )
            ),
        )
