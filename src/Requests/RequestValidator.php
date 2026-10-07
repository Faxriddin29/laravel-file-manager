<?php

namespace Alexusmai\LaravelFileManager\Requests;

use Alexusmai\LaravelFileManager\Services\ConfigService\ConfigRepository;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Storage;
use Illuminate\Validation\Rule;

class RequestValidator extends FormRequest
{
    use CustomErrorMessage;

    /**
     * Determine if the user is authorized to make this request.
     *
     * @return bool
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * Besides "disk"/"path" (checked for every route), each route
     * also has its own request shape (newName/oldName, items,
     * clipboard, elements, name, folder, ...) that was previously
     * never validated at the HTTP boundary - it was only consumed
     * directly via $request->input(...) deeper in the controller/
     * service layer. Validating it here means malformed input is
     * rejected with a normal 422 instead of surfacing as an uncaught
     * TypeError/notice (a potential stack-trace information leak with
     * APP_DEBUG=true), and keeps the security-relevant checks
     * (path/extension/traversal) that the service layer performs from
     * being the *only* layer standing between raw client input and
     * the filesystem.
     *
     * @return array
     */
    public function rules(): array
    {
        $config = resolve(ConfigRepository::class);

        $rules = [
            'disk' => [
                'sometimes',
                'string',
                function ($attribute, $value, $fail) use($config) {
                    if (!in_array($value, $config->getDiskList()) ||
                        !array_key_exists($value, config('filesystems.disks'))
                    ) {
                        return $fail('diskNotFound');
                    }
                },
            ],
            'path' => [
                'sometimes',
                'string',
                'nullable',
                function ($attribute, $value, $fail) {
                    if ($value && !Storage::disk($this->input('disk'))->exists($value)
                    ) {
                        return $fail('pathNotFound');
                    }
                },
            ],
        ];

        return array_merge($rules, $this->routeSpecificRules());
    }

    /**
     * Additional rules for the current route's own input, keyed by
     * route name (set in routes.php).
     *
     * @return array
     */
    protected function routeSpecificRules(): array
    {
        switch ($this->route()?->getName()) {
            case 'fm.upload':
                return [
                    'files'      => ['required', 'array', 'min:1'],
                    'files.*'    => ['file'],
                    'overwrite'  => ['sometimes', 'boolean'],
                ];

            case 'fm.update-file':
                return [
                    'file' => ['required', 'file'],
                ];

            case 'fm.delete':
                return [
                    'items'         => ['required', 'array', 'min:1'],
                    'items.*.path'  => ['required', 'string'],
                    'items.*.type'  => ['required', 'string', Rule::in(['file', 'dir'])],
                ];

            case 'fm.paste':
                return [
                    'clipboard'               => ['required', 'array'],
                    'clipboard.disk'          => ['required', 'string'],
                    'clipboard.type'          => ['required', 'string', Rule::in(['copy', 'cut'])],
                    'clipboard.files'         => ['sometimes', 'array'],
                    'clipboard.files.*'       => ['string'],
                    'clipboard.directories'   => ['sometimes', 'array'],
                    'clipboard.directories.*' => ['string'],
                ];

            case 'fm.rename':
                return [
                    'oldName' => ['required', 'string'],
                    'newName' => ['required', 'string'],
                ];

            case 'fm.create-directory':
            case 'fm.create-file':
                return [
                    'name' => ['required', 'string'],
                ];

            case 'fm.zip':
                return [
                    'name'                   => ['required', 'string'],
                    'elements'               => ['required', 'array'],
                    'elements.files'         => ['sometimes', 'array'],
                    'elements.files.*'       => ['string'],
                    'elements.directories'   => ['sometimes', 'array'],
                    'elements.directories.*' => ['string'],
                ];

            case 'fm.unzip':
                return [
                    'folder' => ['sometimes', 'nullable', 'string'],
                ];

            default:
                return [];
        }
    }

    /**
     * Not found message
     *
     * @return string
     */
    public function message()
    {
        return 'notFound';
    }
}
